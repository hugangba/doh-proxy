# Go DoH ECH Proxy

这是一个使用 Go 语言编写的高性能 **DNS-over-HTTPS (DoH)** 代理服务器。它专门用于解决 SNI 阻断问题，支持 **ECH (Encrypted Client Hello)** 注入、特定域名劫持以及**远程动态自定义解析**。

## 🚀 核心功能

- **标准 DoH 转发**：支持通过 `/doh-proxy` 接口转发标准 DNS 请求至 Google DNS。
- **ECH 配置注入**：针对特定域名（如 Twitter, Meta, Cloudflare）自动注入 ECH 记录，保护 TLS 握手隐私。
- **域名劫持与替换**：
    - 自动识别并劫持 Twitter/X 相关域名，返回指定的清洁 IP。
    - 自动探测 Meta (Facebook/Instagram) 和 Cloudflare 资产并优化解析。
- **远程动态配置**：支持从远程 URL（如 GitHub Gist）实时导入自定义域名解析规则（IPv4, IPv6, ECH），无需重启服务。
- **高性能架构**：采用 Go 协程并发处理，内置内存缓存机制，支持 CIDR 高速匹配。

## 🛠️ 项目结构

代码已进行模块化拆分，便于维护：
- `main.go`: 程序入口、HTTP 路由及基础逻辑。
- `config.go`: 静态配置、Twitter 域名列表及原始 CIDR 数据。
- `remote.go`: 远程 JSON 配置的异步拉取与自动更新。
- `dns_logic.go`: DNS 业务逻辑处理（劫持、探测、ECH 注入）。
- `dns_codec.go`: 底层 DNS 报文编解码工具。
- `cache.go`: 内存缓存管理。

## 📦 快速开始

### 1. 环境准备
确保已安装 **Go 1.21** 或更高版本。

### 2. 下载与初始化
将所有 `.go` 文件放在同一个文件夹中，然后运行：
```bash
go mod init doh-proxy
```

### 3. 配置 CIDR 数据
打开 `config.go`，将原有的 `RAW_META_CIDRS` 和 `RAW_CF_CIDRS` 列表替换为你完整的 CIDR 数据（确保使用双引号 `"`）。

### 4. 运行程序
```bash
# 直接运行
go run .

# 或者编译后运行
go build -o doh-proxy
./doh-proxy
```

## ⚙️ 环境变量

| 变量名 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `PORT` | 服务监听端口 | `8080` |
| `REMOTE_CONFIG_URL` | 远程 JSON 配置文件的公开 URL | (空) |

**示例：**
```bash
PORT=3000 REMOTE_CONFIG_URL="https://raw.githubusercontent.com/user/repo/main/config.json" go run .
```

## 📄 远程 JSON 配置格式

若启用了远程配置，JSON 文件应遵循以下格式：

```json
{
  "domains": {
    "example.com": {
      "ip4": ["1.1.1.1", "1.0.0.1"],
      "ip6": ["2606:4700:4700::1111"],
      "ech": "你的ECH配置Base64字符串"
    },
    "translate.google.com": {
      "ip6": ["2001:470::2"]
    }
  }
}
```

## 🧪 功能测试

可以使用 `curl` 模拟 DNS 查询（Base64 编码）：

### 测试基础转发
```bash
curl -H "accept: application/dns-message" \
"http://localhost:8080/doh-proxy?dns=q80BAAABAAAAAAAAA3d3dwdnb29nbGUDY29tAAABAAE"
```

### 测试自定义 IPv6 解析
```bash
# 查询 translate.google.com 的 AAAA 记录
curl -H "accept: application/dns-message" \
"http://localhost:8080/doh-ech-proxy?dns=AAABAAABAAAAAAAACXRyYW5zbGF0ZQZnb29nbGUDY29tAAAcAAE" | hexdump -C
```

### 测试 Twitter 劫持
```bash
# 查询 twitter.com 的 A 记录
curl -H "accept: application/dns-message" \
"http://localhost:8080/doh-ech-proxy?dns=AAABAAABAAAAAAAAB3R3aXR0ZXIDY29tAAABAAE" | hexdump -C
```

## ⚠️ 免责声明
本工具仅用于网络技术研究与隐私保护测试。请在遵守当地法律法规的前提下使用。
