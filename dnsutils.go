package main

import (
	"net"

	"github.com/miekg/dns"
)

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