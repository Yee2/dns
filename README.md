# dns 分流工具

这是一个简单的DNS分流工具，

### 监听端口

支持开启 UDP、TCP传输方式的DNS服务器。

```toml
[[listen]]
type = "udp"
address = "0.0.0.0:53"

[[listen]]
type = "tcp"
address = "0.0.0.0:53"
```

### 上游DNS配置

上游DNS查询协议支持：

- udp
- tcp
- dns-over-https
- dns-over-https-quic

#### 使用udp查询

```toml
[[upstreams]]
name = "cloudflare"
address = "1.1.1.1:53"
method = "udp"
```

#### 使用tcp查询

```toml
[[upstreams]]
name = "cloudflare-tcp"
address = "1.1.1.1:53"
method = "tcp"
```
#### 使用 DoH查询
Doh有两种模式，一直是使用二进制的数据查询，一种是使用json格式编码数据查询，根据DNS服务器，配置相应的查询方式：

- doh-json
- doh3-json
- doh / doh-wireformat
- doh3 / doh3-wireformat

默认使用 doh-wireformat 格式交换数据，在传输方式上支持 HTTP 和 HTTP3 协议传输，
doh3-wireformat 就是会使用二进制的DNS查询 并且基于 Quic 协议传输，在某些情况下，会有较快的响应。

```toml
[[upstreams]]
name = "cloudflare-doh"
address = "1.1.1.1:53"
method = "doh"
```



### 本地记录

支持下面类型的本地记录：
- A
- AAAA
- TXT
- MX
- NS
- CNAME

```toml
[[records]]
name = "my.router"
type = "A"
ttl = 3600
context = "192.168.1.1"

```

### 分流策略

分流策略采用 `[匹配方式]:[匹配参数]` 的语法，如果 dns 查询命中前面的规则，马上返回结果。

支持以下匹配规则:
- adblock:[filename]
- ipset:[filename]
- prefix:[str]
- suffix:[str]
- contain:[str]
- domain:[str]
- fqdn:[str]
- other

其中 `prefix` / `suffix` / `contain` / `domain` / `fqdn` 是基于请求域名进行文本匹配，`[str]` 部位为匹配内容。

`adblock` / `ipset` 后面附带文件名称，程序会读取相应文件内的规则。 `adblock`匹配采用的是 `AdguardHome`的规则引擎，与`Adguard Home` dns 匹配规则兼容。

`other`表示默认采用规则，轻将 `other` 配置到最后面。

```toml
[[rules]]
name = "other"
upstream = "locale"
```

