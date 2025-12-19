package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSProxy DNS代理
type DNSProxy struct {
	config *Config
	cache  *DNSCache
	// 连接池
	udpConnPool   *UDPConnPool
	dotConnPool   *TLSConnPool
	httpClient    *http.Client
	httpClientMux sync.RWMutex
}

// NewDNSProxy 从配置文件创建DNS代理
func NewDNSProxy(configFile string) (*DNSProxy, error) {
	config, err := loadConfig(configFile)
	if err != nil {
		return nil, err
	}

	proxy := &DNSProxy{
		config: config,
	}

	// 初始化缓存
	if config.CacheConfig.Enabled {
		proxy.cache = NewDNSCache(config.CacheConfig)
		fmt.Printf("DNS缓存已启用，容量: %d，TTL: %d秒\n",
			config.CacheConfig.MaxSize, config.CacheConfig.TTLSeconds)
	}

	// 初始化UDP连接池
	proxy.udpConnPool = NewUDPConnPool(time.Duration(config.TimeoutSeconds) * time.Second)

	// 初始化TLS连接池（用于DoT）
	if len(config.DOTUpstreams) > 0 {
		proxy.dotConnPool = NewTLSConnPool(time.Duration(config.TimeoutSeconds) * time.Second)
	}

	// 初始化HTTP客户端（用于DoH）
	proxy.httpClient = &http.Client{
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		},
	}

	return proxy, nil
}

// 获取超时时间
func (p *DNSProxy) getTimeout() time.Duration {
	return time.Duration(p.config.TimeoutSeconds) * time.Second
}

// 启动DNS代理
func (p *DNSProxy) Start() error {
	fmt.Printf("加载配置:\n")
	fmt.Printf("  监听地址: %s\n", p.config.ListenAddr)
	fmt.Printf("  超时时间: %d秒\n", p.config.TimeoutSeconds)
	fmt.Printf("  调试模式: %v\n", p.config.Debug)
	fmt.Printf("  缓存: %v\n", p.config.CacheConfig.Enabled)
	fmt.Printf("  UDP上游: %v\n", p.config.UDPUpstreams)
	fmt.Printf("  DoT上游: %v\n", p.config.DOTUpstreams)
	fmt.Printf("  DoH上游: %v\n", p.config.DOHUpstreams)
	fmt.Println()

	// 启动UDP监听
	go p.startUDP()
	// 启动TCP监听
	go p.startTCP()

	fmt.Printf("DNS代理已启动，监听地址: %s\n", p.config.ListenAddr)
	select {}
}

// 启动UDP监听
func (p *DNSProxy) startUDP() error {
	udpAddr, err := net.ResolveUDPAddr("udp", p.config.ListenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buffer := make([]byte, 65535) // UDP最大包大小

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		go p.handleUDPRequest(conn, addr, buffer[:n])
	}
}

// 启动TCP监听
func (p *DNSProxy) startTCP() error {
	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go p.handleTCPRequest(conn)
	}
}

// 处理UDP请求
func (p *DNSProxy) handleUDPRequest(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	msg := new(dns.Msg)
	err := msg.Unpack(data)
	if err != nil {
		return
	}

	// 添加OPT记录（如果不存在）
	if !hasOPTRecord(msg) {
		msg.SetEdns0(4096, false)
		if p.config.Debug {
			fmt.Printf("[UDP] 客户端请求没有OPT记录，已添加: %s\n", msg.Question[0].Name)
		}
	}

	// 处理请求
	response := p.processRequest(msg)
	if response == nil {
		return
	}

	// 发送响应
	responseData, err := response.Pack()
	if err != nil {
		return
	}

	conn.WriteToUDP(responseData, addr)
}

// 处理TCP请求
func (p *DNSProxy) handleTCPRequest(conn net.Conn) {
	defer conn.Close()

	// 读取长度前缀
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return
	}

	// 读取数据
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return
	}

	// 解析DNS消息
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return
	}

	// 添加OPT记录（如果不存在）
	if !hasOPTRecord(msg) {
		msg.SetEdns0(4096, false)
		if p.config.Debug {
			fmt.Printf("[TCP] 客户端请求没有OPT记录，已添加: %s\n", msg.Question[0].Name)
		}
	}

	// 处理请求
	response := p.processRequest(msg)
	if response == nil {
		return
	}

	// 打包响应
	responseData, err := response.Pack()
	if err != nil {
		return
	}

	// 写入长度前缀和响应
	responseLength := uint16(len(responseData))
	binary.Write(conn, binary.BigEndian, responseLength)
	conn.Write(responseData)
}

// 处理DNS请求
func (p *DNSProxy) processRequest(msg *dns.Msg) *dns.Msg {
	// 检查缓存
	if p.config.CacheConfig.Enabled && p.cache != nil {
		if cached := p.cache.Get(msg); cached != nil {
			if p.config.Debug {
				fmt.Printf("缓存命中: %s\n", msg.Question[0].Name)
			}
			// 需要复制消息并设置正确的ID
			response := cached.Copy()
			response.Id = msg.Id
			return response
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.getTimeout())
	defer cancel()

	// 并行请求UDP上游
	responses := make(chan *dns.Msg, len(p.config.UDPUpstreams))
	var wg sync.WaitGroup

	// 启动所有UDP上游查询
	for _, upstream := range p.config.UDPUpstreams {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			if resp := p.queryUDPUpstream(ctx, msg, server); resp != nil {
				select {
				case responses <- resp:
				case <-ctx.Done():
				}
			}
		}(upstream)
	}

	// 等待第一个EDNS响应
	var validResponse *dns.Msg
	var hasTruncatedResponse bool
	
	// 超时控制
	timeout := time.After(p.getTimeout())
	
	// 收集响应，优先选择有EDNS的
	for i := 0; i < len(p.config.UDPUpstreams); i++ {
		select {
		case resp := <-responses:
			if resp != nil {
				// 检查是否是截断响应
				if resp.Rcode == 0xFF {
					hasTruncatedResponse = true
					if p.config.Debug {
						fmt.Printf("收到截断响应，需要回退到安全传输: %s\n", msg.Question[0].Name)
					}
					continue
				}
				
				// 首先检查是否是EDNS响应
				if hasOPTRecord(resp) {
					validResponse = resp
					if p.config.Debug {
						fmt.Printf("从UDP上游获得EDNS响应，立即返回: %s\n", msg.Question[0].Name)
					}
					// 取消上下文，停止其他查询
					cancel()
					break
				}
				// 如果没有EDNS响应，暂时保存
				if validResponse == nil && isValidResponse(resp) {
					validResponse = resp
				}
			}
		case <-timeout:
			if p.config.Debug {
				fmt.Printf("UDP查询超时: %s\n", msg.Question[0].Name)
			}
			break
		}
		// 如果已经找到EDNS响应，跳出循环
		if validResponse != nil && hasOPTRecord(validResponse) {
			break
		}
	}

	// 如果收到了截断响应，直接回退到安全传输
	if hasTruncatedResponse {
		if p.config.Debug {
			fmt.Printf("有UDP响应被截断，直接回退到安全传输: %s\n", msg.Question[0].Name)
		}
		// 取消UDP查询（如果还有在进行的话）
		cancel()
		goto fallbackToSecure
	}

	// 如果找到了EDNS响应，直接返回
	if validResponse != nil && hasOPTRecord(validResponse) {
		// 缓存响应
		if p.config.CacheConfig.Enabled && p.cache != nil {
			p.cache.Set(msg, validResponse)
		}
		// 需要复制消息并设置正确的ID
		response := validResponse.Copy()
		response.Id = msg.Id
		return response
	}
	
	// 如果没有EDNS响应，但有其他有效响应，也返回
	if validResponse != nil {
		// 缓存响应
		if p.config.CacheConfig.Enabled && p.cache != nil {
			p.cache.Set(msg, validResponse)
		}
		// 需要复制消息并设置正确的ID
		response := validResponse.Copy()
		response.Id = msg.Id
		return response
	}

fallbackToSecure:
	// UDP上游没有有效响应或有截断响应，尝试DoT/DoH
	if len(p.config.DOTUpstreams) > 0 || len(p.config.DOHUpstreams) > 0 {
		if p.config.Debug {
			fmt.Printf("回落到安全传输: %s\n", msg.Question[0].Name)
		}
		// 为安全上游创建新的上下文
		secureCtx, secureCancel := context.WithTimeout(context.Background(), p.getTimeout())
		defer secureCancel()
		
		response := p.fallbackToSecureUpstreams(secureCtx, msg)
		if response != nil {
			// 缓存响应
			if p.config.CacheConfig.Enabled && p.cache != nil {
				p.cache.Set(msg, response)
			}
			// 需要复制消息并设置正确的ID
			respCopy := response.Copy()
			respCopy.Id = msg.Id
			return respCopy
		}
	}

	// 没有设置安全上游，返回错误
	if p.config.Debug {
		fmt.Printf("所有上游都失败: %s\n", msg.Question[0].Name)
	}
	return createErrorResponse(msg, dns.RcodeServerFailure)
}