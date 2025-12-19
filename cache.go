package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

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