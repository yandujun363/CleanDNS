package main

import (
	"encoding/json"
	"fmt"
	"os"
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