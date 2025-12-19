package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Config DNS代理配置结构体
type Config struct {
	// UDP上游服务器列表
	UDPUpstreams []string `json:"udp_upstreams"`
	// DoT上游服务器列表
	DOTUpstreams []string `json:"dot_upstreams"`
	// DoH上游服务器列表
	DOHUpstreams []string `json:"doh_upstreams"`
	// 监听地址
	ListenAddr string `json:"listen_addr"`
	// 超时时间（秒）
	TimeoutSeconds int `json:"timeout_seconds"`
	// 是否开启调试
	Debug bool `json:"debug"`
	// 缓存配置
	CacheConfig CacheConfig `json:"cache_config"`
}

// CacheConfig 缓存配置
type CacheConfig struct {
	// 启用缓存
	Enabled bool `json:"enabled"`
	// 缓存最大容量
	MaxSize int `json:"max_size"`
	// 缓存TTL（秒）
	TTLSeconds int `json:"ttl_seconds"`
	// 最小缓存TTL（秒）
	MinTTLSeconds int `json:"min_ttl_seconds"`
}

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

// loadConfig 从JSON文件加载配置
func loadConfig(configFile string) (*Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 设置默认值
	if config.ListenAddr == "" {
		config.ListenAddr = ":53"
	}
	if config.TimeoutSeconds <= 0 {
		config.TimeoutSeconds = 2
	}
	if config.CacheConfig.MaxSize <= 0 {
		config.CacheConfig.MaxSize = 10000
	}
	if config.CacheConfig.TTLSeconds <= 0 {
		config.CacheConfig.TTLSeconds = 300
	}
	if config.CacheConfig.MinTTLSeconds <= 0 {
		config.CacheConfig.MinTTLSeconds = 1
	}

	return &config, nil
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

	buffer := make([]byte, 4096)

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

	// 等待第一个有效响应
	var validResponse *dns.Msg
	deadline := time.After(p.getTimeout())

	for i := 0; i < len(p.config.UDPUpstreams); i++ {
		select {
		case resp := <-responses:
			if isValidResponse(resp) {
				validResponse = resp
				if p.config.Debug {
					fmt.Printf("从UDP上游获得有效响应: %s\n", msg.Question[0].Name)
				}
				break
			}
		case <-deadline:
			break
		}
		if validResponse != nil {
			break
		}
	}

	// 如果从UDP获得了有效响应，直接返回
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

	// UDP上游没有有效响应，尝试DoT/DoH
	if len(p.config.DOTUpstreams) > 0 || len(p.config.DOHUpstreams) > 0 {
		response := p.fallbackToSecureUpstreams(ctx, msg)
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
	return createErrorResponse(msg, dns.RcodeServerFailure)
}

// 查询UDP上游（使用连接池）
func (p *DNSProxy) queryUDPUpstream(ctx context.Context, msg *dns.Msg, upstream string) *dns.Msg {
	// 从连接池获取连接
	conn, err := p.udpConnPool.Get(upstream)
	if err != nil {
		return nil
	}
	defer p.udpConnPool.Put(upstream, conn)

	// 发送请求
	data, err := msg.Pack()
	if err != nil {
		return nil
	}

	if _, err := conn.Write(data); err != nil {
		return nil
	}

	// 接收响应
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(p.getTimeout()))
	n, err := conn.Read(buffer)
	if err != nil {
		return nil
	}

	// 解析响应
	response := new(dns.Msg)
	if err := response.Unpack(buffer[:n]); err != nil {
		return nil
	}

	// 检查响应是否被截断
	if response.Truncated {
		if p.config.Debug {
			fmt.Printf("UDP响应被截断，回落到安全传输: %s\n", msg.Question[0].Name)
		}
		return nil
	}

	return response
}

// 回落到安全上游（DoT/DoH）
func (p *DNSProxy) fallbackToSecureUpstreams(ctx context.Context, msg *dns.Msg) *dns.Msg {
	responses := make(chan *dns.Msg, len(p.config.DOTUpstreams)+len(p.config.DOHUpstreams))
	var wg sync.WaitGroup

	// 并行请求DoT上游
	for _, upstream := range p.config.DOTUpstreams {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			if resp := p.queryDOTUpstream(ctx, msg, server); resp != nil {
				select {
				case responses <- resp:
				case <-ctx.Done():
				}
			}
		}(upstream)
	}

	// 并行请求DoH上游
	for _, upstream := range p.config.DOHUpstreams {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			if resp := p.queryDOHUpstream(ctx, msg, server); resp != nil {
				select {
				case responses <- resp:
				case <-ctx.Done():
				}
			}
		}(upstream)
	}

	// 等待响应
	select {
	case resp := <-responses:
		if isValidResponse(resp) {
			if p.config.Debug {
				fmt.Printf("从安全上游获得有效响应: %s\n", msg.Question[0].Name)
			}
			return resp
		}
	case <-ctx.Done():
		break
	}

	// 所有安全上游都失败，返回错误
	return createErrorResponse(msg, dns.RcodeServerFailure)
}

// 查询DoT上游（使用连接池）
func (p *DNSProxy) queryDOTUpstream(ctx context.Context, msg *dns.Msg, upstream string) *dns.Msg {
	if p.dotConnPool == nil {
		return nil
	}

	// 从连接池获取连接
	conn, err := p.dotConnPool.Get(upstream)
	if err != nil {
		return nil
	}
	defer p.dotConnPool.Put(upstream, conn)

	// 发送DNS请求
	co := &dns.Conn{Conn: conn}
	if err := co.WriteMsg(msg); err != nil {
		return nil
	}

	// 读取响应
	response, err := co.ReadMsg()
	if err != nil {
		return nil
	}

	return response
}

// 查询DoH上游（使用连接复用）
func (p *DNSProxy) queryDOHUpstream(ctx context.Context, msg *dns.Msg, upstream string) *dns.Msg {
	// 打包DNS消息
	data, err := msg.Pack()
	if err != nil {
		return nil
	}

	// Base64编码
	dnsParam := base64.RawURLEncoding.EncodeToString(data)

	// 构建请求URL
	u, err := url.Parse(upstream)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set("dns", dnsParam)
	u.RawQuery = q.Encode()

	// 发送请求
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// 解析响应
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil
	}

	return response
}

// ============================ 缓存实现 ============================

// CacheEntry 缓存条目
type CacheEntry struct {
	msg      *dns.Msg
	added    time.Time
	expireAt time.Time
}

// DNSCache DNS缓存
type DNSCache struct {
	config CacheConfig
	cache  map[string]*CacheEntry
	mu     sync.RWMutex
	keys   []string // LRU顺序
}

// NewDNSCache 创建DNS缓存
func NewDNSCache(config CacheConfig) *DNSCache {
	return &DNSCache{
		config: config,
		cache:  make(map[string]*CacheEntry),
		keys:   make([]string, 0, config.MaxSize),
	}
}

// Get 从缓存获取DNS响应
func (c *DNSCache) Get(msg *dns.Msg) *dns.Msg {
	if msg == nil || len(msg.Question) == 0 {
		return nil
	}

	key := c.generateKey(msg)
	c.mu.RLock()
	entry, exists := c.cache[key]
	c.mu.RUnlock()

	if !exists {
		return nil
	}

	// 检查是否过期
	if time.Now().After(entry.expireAt) {
		c.mu.Lock()
		delete(c.cache, key)
		c.removeKey(key)
		c.mu.Unlock()
		return nil
	}

	return entry.msg
}

// Set 设置DNS响应到缓存
func (c *DNSCache) Set(query, response *dns.Msg) {
	if query == nil || response == nil || len(query.Question) == 0 {
		return
	}

	// 检查响应码，只缓存成功的响应
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return
	}

	// 获取最小TTL
	minTTL := c.getMinTTL(response)
	if minTTL <= 0 {
		return
	}

	// 应用最小缓存TTL配置
	if minTTL < time.Duration(c.config.MinTTLSeconds)*time.Second {
		minTTL = time.Duration(c.config.MinTTLSeconds) * time.Second
	}
	if minTTL > time.Duration(c.config.TTLSeconds)*time.Second {
		minTTL = time.Duration(c.config.TTLSeconds) * time.Second
	}

	key := c.generateKey(query)
	entry := &CacheEntry{
		msg:      response.Copy(),
		added:    time.Now(),
		expireAt: time.Now().Add(minTTL),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 如果缓存已满，移除最旧的条目
	if len(c.keys) >= c.config.MaxSize {
		oldestKey := c.keys[0]
		delete(c.cache, oldestKey)
		c.keys = c.keys[1:]
	}

	// 添加新条目
	c.cache[key] = entry
	c.keys = append(c.keys, key)
}

// generateKey 生成缓存键
func (c *DNSCache) generateKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qtype, q.Qclass)
}

// getMinTTL 获取响应中的最小TTL
func (c *DNSCache) getMinTTL(msg *dns.Msg) time.Duration {
	var minTTL uint32 = ^uint32(0)

	// 检查答案部分
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	// 检查权威部分
	for _, rr := range msg.Ns {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	// 检查附加部分（排除OPT记录）
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	if minTTL == ^uint32(0) {
		return 0
	}

	return time.Duration(minTTL) * time.Second
}

// removeKey 从keys切片中移除指定的key
func (c *DNSCache) removeKey(key string) {
	for i, k := range c.keys {
		if k == key {
			c.keys = append(c.keys[:i], c.keys[i+1:]...)
			break
		}
	}
}

// ============================ 连接池实现 ============================

// UDPConnPool UDP连接池
type UDPConnPool struct {
	pool   map[string]*sync.Pool
	mu     sync.RWMutex
	ttl    time.Duration
	timers map[string]*time.Timer
}

// NewUDPConnPool 创建UDP连接池
func NewUDPConnPool(ttl time.Duration) *UDPConnPool {
	return &UDPConnPool{
		pool:   make(map[string]*sync.Pool),
		ttl:    ttl,
		timers: make(map[string]*time.Timer),
	}
}

// Get 从连接池获取连接
func (p *UDPConnPool) Get(addr string) (net.Conn, error) {
	p.mu.RLock()
	pool, exists := p.pool[addr]
	p.mu.RUnlock()

	if exists {
		if conn := pool.Get(); conn != nil {
			return conn.(net.Conn), nil
		}
	}

	// 创建新连接
	conn, err := net.DialTimeout("udp", addr, p.ttl)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Put 将连接放回连接池
func (p *UDPConnPool) Put(addr string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	pool, exists := p.pool[addr]
	if !exists {
		pool = &sync.Pool{
			New: func() interface{} {
				newConn, err := net.DialTimeout("udp", addr, p.ttl)
				if err != nil {
					return nil
				}
				return newConn
			},
		}
		p.pool[addr] = pool
	}

	pool.Put(conn)

	// 设置定时器清理空闲连接
	if timer, exists := p.timers[addr]; exists {
		timer.Stop()
	}
	p.timers[addr] = time.AfterFunc(p.ttl*2, func() {
		p.cleanup(addr)
	})
}

// cleanup 清理指定地址的连接池
func (p *UDPConnPool) cleanup(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if pool, exists := p.pool[addr]; exists {
		if conn := pool.Get(); conn != nil {
			conn.(net.Conn).Close()
		}
		delete(p.pool, addr)
		delete(p.timers, addr)
	}
}

// TLSConnPool TLS连接池
type TLSConnPool struct {
	pool   map[string]*sync.Pool
	mu     sync.RWMutex
	ttl    time.Duration
	config *tls.Config
}

// NewTLSConnPool 创建TLS连接池
func NewTLSConnPool(ttl time.Duration) *TLSConnPool {
	return &TLSConnPool{
		pool: make(map[string]*sync.Pool),
		ttl:  ttl,
		config: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
}

// Get 从连接池获取连接
func (p *TLSConnPool) Get(addr string) (net.Conn, error) {
	p.mu.RLock()
	pool, exists := p.pool[addr]
	p.mu.RUnlock()

	if exists {
		if conn := pool.Get(); conn != nil {
			return conn.(net.Conn), nil
		}
	}

	// 创建新连接
	p.mu.Lock()
	if p.config.ServerName == "" {
		p.config.ServerName = extractServerName(addr)
	}
	p.mu.Unlock()

	dialer := &net.Dialer{
		Timeout: p.ttl,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, p.config)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Put 将连接放回连接池
func (p *TLSConnPool) Put(addr string, conn net.Conn) {
	p.mu.Lock()
	pool, exists := p.pool[addr]
	if !exists {
		pool = &sync.Pool{
			New: func() interface{} {
				dialer := &net.Dialer{
					Timeout: p.ttl,
				}
				newConn, err := tls.DialWithDialer(dialer, "tcp", addr, p.config)
				if err != nil {
					return nil
				}
				return newConn
			},
		}
		p.pool[addr] = pool
	}
	p.mu.Unlock()

	pool.Put(conn)
}

// ============================ 工具函数 ============================

// 检查响应是否有效
func isValidResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}

	// 1. 检查是否有OPT记录
	if hasOPTRecord(msg) {
		return true
	}

	// 2. 检查是否有多个答案
	if len(msg.Answer) > 1 {
		return true
	}

	// 3. 对于NXDOMAIN，检查是否有SOA记录
	if msg.Rcode == dns.RcodeNameError {
		for _, rr := range msg.Ns {
			if _, ok := rr.(*dns.SOA); ok {
				return true
			}
		}
	}

	// 4. 检查是否有权威信息
	if len(msg.Ns) > 0 {
		return true
	}

	return false
}

// 检查消息是否有OPT记录
func hasOPTRecord(msg *dns.Msg) bool {
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			return true
		}
	}
	return false
}

// 提取服务器名称
func extractServerName(upstream string) string {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return upstream
	}
	return host
}

// 创建错误响应
func createErrorResponse(original *dns.Msg, rcode int) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(original, rcode)
	response.RecursionAvailable = true
	response.Compress = false

	// 添加OPT记录
	response.SetEdns0(4096, false)

	return response
}

func main() {
	// 检查配置文件参数
	if len(os.Args) < 2 {
		fmt.Println("使用方法: cleandns <配置文件路径>")
		fmt.Println("示例: cleandns config.json")
		os.Exit(1)
	}

	configFile := os.Args[1]

	// 创建DNS代理
	proxy, err := NewDNSProxy(configFile)
	if err != nil {
		fmt.Printf("创建DNS代理失败: %v\n", err)
		os.Exit(1)
	}

	// 启动DNS代理
	if err := proxy.Start(); err != nil {
		fmt.Printf("启动失败: %v\n", err)
		os.Exit(1)
	}
}