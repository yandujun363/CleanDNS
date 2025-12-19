# CleanDNS

**注意：本项目只是[在敌对网络中精准甄别DNS真实响应](https://www.yangdujun.top/opus/105)的简单实现，高QPS和大并发情况下肯定爆炸，并且在OpenWrt上测试有各种乱七八糟的奇妙BUG，不推荐生成环境使用，但是实现原理可以参考，个人推荐提交issues到[pymumu/smartdns](https://github.com/pymumu/smartdns/)或者[AdguardTeam/AdGuardHome](https://github.com/AdguardTeam/AdGuardHome)，让专业开发的写出这个功能，本项目的全部代码都是AI写的，肯定有一堆BUG**

一个简单高效的DNS代理，支持UDP/TCP/DoT/DoH协议。

## 快速开始

### 1. 编译项目

```bash
go build -o cleandns main.go
```

### 2. 配置文件

创建 `config.json` 文件：

```json
{
  "listen_addr": "0.0.0.0:53",
  "timeout_seconds": 3,
  "debug": true,
  "cache_config": {
    "enabled": true,
    "max_size": 10000,
    "ttl_seconds": 300,
    "min_ttl_seconds": 1
  },
  "udp_upstreams": [
    "101.101.101.101:53",
    "1.1.1.1:53",
    "8.8.8.8:53"
  ],
  "dot_upstreams": [
    "1dot1dot1dot1.cloudflare-dns.com:853"
  ],
  "doh_upstreams": [
    "https://77.88.8.8/dns-query",
    "https://77.88.8.1/dns-query"
  ]
}
```

### 3. 运行服务

```bash
./cleandns config.json
```

## 配置说明

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `listen_addr` | 监听地址和端口 | `"0.0.0.0:53"` |
| `timeout_seconds` | 查询超时时间（秒） | `3` |
| `debug` | 启用调试日志 | `true` |
| `udp_upstreams` | UDP上游服务器列表 | `["101.101.101.101:53","1.1.1.1:53","8.8.8.8:53"]` |
| `dot_upstreams` | DoT上游服务器列表 | `["1dot1dot1dot1.cloudflare-dns.com:853"]` |
| `doh_upstreams` | DoH上游服务器列表 | `["https://77.88.8.8/dns-query","https://77.88.8.1/dns-query"]` |
| **`cache_config`** | **DNS缓存配置** | **见下方子表** |

## `cache_config` 子配置项说明

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `enabled` | 是否启用DNS缓存 | `true` |
| `max_size` | 缓存最大条目数 | `10000` |
| `ttl_seconds` | 缓存条目的默认生存时间（秒）。如果DNS响应的TTL更长，则以此值为准。 | `300` |
| `min_ttl_seconds` | 缓存条目的最小生存时间（秒）。即使DNS响应的TTL更短，也会至少缓存此时间。 | `1` |

### 上游服务器示例

**UDP服务器：**
- Cloudflare: `1.1.1.1:53`
- Google: `8.8.8.8:53`
- Quad9: `9.9.9.9:53`

**DoT服务器：**
- Cloudflare: `1dot1dot1dot1.cloudflare-dns.com:853`
- Google: `dns.google:853`

**DoH服务器：**
- Yandex: `https://77.88.8.8/dns-query`
- Cloudflare: `https://cloudflare-dns.com/dns-query`

## 使用示例

### 基本使用

```bash
# 使用默认配置
./cleandns config.json
```

### 测试DNS解析

```bash
# 使用dig测试
dig @127.0.0.1 example.com

# 使用nslookup测试
nslookup example.com 127.0.0.1
```

## 工作原理

1. 客户端发送DNS查询到CleanDNS
2. CleanDNS首先尝试所有UDP上游服务器
3. 如果UDP查询失败或超时，回退到DoT/DoH上游
4. 返回第一个有效响应给客户端
5. 自动为没有OPT记录的请求添加OPT记录

## 故障排除

### 常见问题

1. **权限问题**
   - Linux/Mac: 需要root权限监听53端口
   ```bash
   sudo ./cleandns config.json
   ```

2. **端口冲突**
   - 检查53端口是否被其他服务占用
   ```bash
   sudo netstat -tulpn | grep :53
   ```

3. **上游服务器不可达**
   - 检查网络连接
   - 验证上游服务器地址和端口

### 调试模式

启用调试模式查看详细日志：

```json
{
  "debug": true,
  ...
}
```

## 依赖

- Go 1.25.5+
- github.com/miekg/dns

## 构建和安装

```bash
# 下载依赖
go mod download

# 构建
go build -o cleandns .

# 安装到系统路径
sudo cp cleandns /usr/local/bin/
```

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request。