package main

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// UDPConnPool UDP连接池（现在基本不用，但保留接口）
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

// Get 从连接池获取连接（现在总是返回新连接）
func (p *UDPConnPool) Get(addr string) (net.Conn, error) {
	// 总是创建新连接
	conn, err := net.DialTimeout("udp", addr, p.ttl)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Put 将连接放回连接池（现在直接关闭）
func (p *UDPConnPool) Put(addr string, conn net.Conn) {
	// 直接关闭连接
	conn.Close()
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