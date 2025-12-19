package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// queryUDPUpstream 查询UDP上游（不使用连接池，每个请求独立连接）
func (p *DNSProxy) queryUDPUpstream(ctx context.Context, msg *dns.Msg, upstream string) *dns.Msg {
	// 创建新的UDP连接（不使用连接池）
	conn, err := net.DialTimeout("udp", upstream, p.getTimeout())
	if err != nil {
		if p.config.Debug {
			fmt.Printf("连接到UDP上游失败 %s: %v\n", upstream, err)
		}
		return nil
	}
	defer conn.Close()

	// 发送请求
	data, err := msg.Pack()
	if err != nil {
		return nil
	}

	if _, err := conn.Write(data); err != nil {
		return nil
	}

	// 接收响应 - 使用足够大的缓冲区
	buffer := make([]byte, 65535) // UDP最大包大小
	
	// 设置总超时
	deadline := time.Now().Add(p.getTimeout())
	
	// 收集所有可能的响应
	var responses []*dns.Msg
	
	for time.Now().Before(deadline) {
		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		
		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时，检查是否已经收到有效响应
				break
			}
			// 其他错误，继续等待
			continue
		}

		// 尝试解析响应
		response := new(dns.Msg)
		if err := response.Unpack(buffer[:n]); err != nil {
			continue
		}

		// 检查是否是我们请求的响应
		if response.Id == msg.Id {
			responses = append(responses, response)
			
			// 检查响应是否被截断
			if response.Truncated {
				if p.config.Debug {
					fmt.Printf("UDP响应被截断，回落到安全传输: %s\n", msg.Question[0].Name)
				}
				return nil
			}
			
			// 检查是否有OPT记录（EDNS）
			if hasOPTRecord(response) {
				if p.config.Debug {
					fmt.Printf("从 %s 收到EDNS响应: %s\n", upstream, msg.Question[0].Name)
				}
				return response
			}
			
			if p.config.Debug {
				fmt.Printf("从 %s 收到非EDNS响应: %s (继续等待EDNS响应)\n", upstream, msg.Question[0].Name)
			}
		}
	}
	
	// 如果收到了响应但没有EDNS，检查其他有效性标准
	for _, response := range responses {
		if isValidResponse(response) {
			if p.config.Debug {
				fmt.Printf("从 %s 收到有效非EDNS响应: %s\n", upstream, msg.Question[0].Name)
			}
			return response
		}
	}
	
	// 如果没有收到任何有效响应
	if p.config.Debug && len(responses) > 0 {
		fmt.Printf("从 %s 收到 %d 个响应但都不符合有效性标准: %s\n", 
			upstream, len(responses), msg.Question[0].Name)
	}
	
	return nil
}

// queryDOTUpstream 查询DoT上游（使用连接池）
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

// queryDOHUpstream 查询DoH上游（使用连接复用）
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

// fallbackToSecureUpstreams 回落到安全上游（DoT/DoH）
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