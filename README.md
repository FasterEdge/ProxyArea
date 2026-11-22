<div align="center">
  <img src="./Logo.png" alt="ProxyArea logo" width="100" />
  <h2>ProxyArea</h2>
  <h3>轻量、安全、纯 Go 标准库实现的 REST 兼容 HTTP 转发器</h3>
</div>

### 一、项目简介

ProxyArea 是 FasterEdge 生态中的轻量级 REST 兼容 HTTP 转发器,纯 Go 标准库实现,当前版本 `1.0.20261116`。

- 提供 `/get`、`/post`、`/put`、`/patch`、`/delete`、`/head`、`/options`、`/proxy`、`/healthz` 等固定路由,所有路由、所有方法按字节保留业务 body。
- 控制字段来源 query / 显式 JSON envelope / form,认证优先级 `Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form。
- 白名单按 `URL.Hostname()` 大小写无关精确匹配,并在每次重定向重新验证,默认最多 10 跳。
- 除了主机名白名单,还对**DNS 解析后的 IP** 做统一校验:forward、重定向、CONNECT 三条路径共用同一函数,拒绝回环/私网/链路本地/未指定地址及 IPv4-mapped IPv6 绕过,并在拨号阶段按已校验的 IP 连接以关闭 DNS rebinding 窗口。
- 非控制类(透传)请求体与上游响应体都有上限(默认 16 MiB / 64 MiB,可用 `--max-request-body`、`--max-response-body` 调整),超限返回 413/502 或中断连接,不返回被截断的"成功"响应。

### 二、启动

```bash
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=127.0.0.1,api.internal
```

现有 CLI 保持兼容:`--addr`、`--key`、`--https`、`--cert_file`、`--key_file`、`--timeout`、`--target-scheme`、`--allow-hosts`、`--insecure-skip-verify`。

本次新增(均有默认值,不配即用):

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--allow-private-nets` | `false` | 放行回环/私网/链路本地目标; 仅限受控内网与本地测试 |
| `--max-request-body` | `16MiB` | 透传(非控制类)请求体上限 |
| `--max-response-body` | `64MiB` | 上游响应体上限 |

上限参数接受纯数字(字节)或带单位写法:`16MiB`、`64MB`、`1KiB`、`1B`。

### 三、路由

| 路径 | 上游方法 |
|---|---|
| `/get` | GET |
| `/post` | POST |
| `/put` | PUT |
| `/patch` | PATCH |
| `/delete` | DELETE |
| `/head` | HEAD |
| `/options` | OPTIONS |
| `/proxy` | 客户端原方法,包括 PROPFIND 等扩展方法 |
| `/healthz` | 健康检查(返回 200 OK) |

未知或更深的 `/proxy/...` 返回 404。所有路由、所有方法都会按字节保留业务 body,包括 GET、HEAD、OPTIONS 和 DELETE;没有 body 时不会自动添加 Content-Type。

### 四、控制字段

`url` 必填;`params` 会解析后合并到目标 query(重复键保留且只编码一次);`https` 仅接受布尔值并仅在 URL 无协议时生效;`key` 用于兼容认证。

非认证控制字段优先级为 **query → 显式 JSON envelope → form**。认证优先级为 **`Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form**。高优先级来源一旦出现,即使为空或错误也不会回退。

普通 `application/json` 永远是业务 body:

```bash
curl -X PATCH 'http://127.0.0.1:8080/proxy?url=http%3A%2F%2Fapi.internal%2Fitems%2F1' \
  -H 'Authorization: Bearer my_secret' -H 'Content-Type: application/json' \
  -d '{"name":"new"}'
```

urlencoded 与 multipart 可携带 `url`、`params`、`https`、`key`,并会把原始表单(包括控制字段)完整转发。业务表单推荐把控制字段放 query、认证放 Header。

#### 显式 JSON envelope

媒体类型:`application/vnd.proxyarea.proxy+json`。

```json
{
  "url": "https://api.internal/items",
  "params": "trace=1&tag=a&tag=b",
  "https": true,
  "key": "my_secret",
  "encoding": "json",
  "body": {"name":"new"},
  "contentType": "application/json"
}
```

`encoding` 支持:`none`(默认且不得带 body)、`json`、`text`、`base64`。未知字段、额外 JSON 值、无效编码/base64/contentType 均返回 400;控制 body 上限 8 MiB,超限返回 413。

### 五、URL、Header 与错误

仅允许 http/https,拒绝 userinfo、控制字符、缺少 hostname 和非法端口。无协议 URL 使用 `https=true` 或 `--target-scheme`。白名单按 `URL.Hostname()` 大小写无关精确匹配,并在每次重定向重新验证,默认最多 10 跳。主机名匹配之外,每一跳还会对 DNS 解析结果做 IP 分类校验,详见第六节。

请求和响应都移除标准 hop-by-hop Header 及 `Connection` 动态指定的 Header;不转发 Host、Content-Length、Authorization、X-Proxy-Key。多值端到端 Header(例如 Set-Cookie)保留。

错误映射:400 控制/URL 错误,401 认证失败,403 白名单或解析后 IP 校验拒绝,404 未知别名,413 请求体(控制类或透传)超限,502 上游/重定向失败、DNS 解析失败或响应体超限,504 超时。

### 六、安全

ProxyArea 是一个可访问任意目标的转发器，因此安全边界必须同时看**白名单**和**解析后 IP**两道关：

**第一道：目标白名单。** `--allow-hosts` 为空时允许任意目标（包括私网），此时唯一防线是第二道。配置后按 `URL.Hostname()` 大小写无关精确匹配，条目支持 `host`（不限端口）与 `host:port`（精确匹配主机+端口，防止 `/connect` 对白名单主机做任意端口扫描）两种形式；每一跳重定向都会重新匹配。

**第二道：解析后 IP 校验。** 白名单匹配的是主机名，而 `buildTargetURL` 之后真正连到哪里，取决于 DNS 返回什么。因此 forward、重定向、CONNECT 三条路径共用同一个校验函数（`proxy.go:validateTarget` → `netguard.go:checkResolvedIPs`），把 DNS 解析结果逐一分类，命中以下网段即整体拒绝——只要有一个解析结果是内网地址，整个目标就被拒绝，不会挑一个"看起来安全"的 IP 来连：

| 网段 | 说明 |
|---|---|
| `127.0.0.0/8`、`::1` | 回环 |
| `10/8`、`172.16/12`、`192.168/16`、`fc00::/7` | 私网 |
| `169.254.0.0/16`、`fe80::/10` | 链路本地（含云元数据 `169.254.169.254`） |
| `100.64.0.0/10` | 运营商级 NAT |
| `0.0.0.0`、`::` | 未指定地址 |
| 组播、保留段 | 同上 |

IPv4-mapped IPv6（`::ffff:10.0.0.1` 这类写法）会先归一化为 IPv4 再分类，否则按 IPv6 前缀判定会漏掉。

**DNS rebinding。** 光"先校验、再让 HTTP 客户端自己解析"仍有一个窗口：攻击者可在两次 DNS 查询之间把答案改成内网地址。ProxyArea 的做法是在 `Transport.DialContext` 上安装拨号钩子（`netguard.go:dialGuarded`），**解析、校验、连接使用同一份结果**，直接连接校验过的那个 IP。这样即使 DNS 在校验之后被改写，实际连接的目标不变。传入的 Transport 会被克隆后才安装钩子，不会污染进程全局的 `http.DefaultTransport`。

**请求体与响应体上限。** 非控制类 Content-Type 的 body 原本是原样流式透传、无上限，可被无限流式上传打满内存与带宽。现在：

| 上限 | 默认值 | CLI | 超限行为 |
|---|---|---|---|
| 透传请求体 | 16 MiB | `--max-request-body` | 已知长度 → 413；chunked 边读边计数，超限 → 413 |
| 上游响应体 | 64 MiB | `--max-response-body` | 已知长度 → 502；chunked 中断连接，客户端看到传输失败 |
| 控制类 body | 8 MiB | 不可配置 | 413 |

超限返回的是明确的 413/502 或连接中断，**不会**把截断后的内容当成成功响应返回。参数既接受纯数字（字节）也接受 `16MiB`/`64MB` 这类写法。

**部署要求。** 未配置 `--key` 时认证关闭，公网部署必须同时配置 `--key` 与 `--allow-hosts`。`--allow-private-nets` 会放行回环/私网/链路本地地址，仅供受控内网与本地测试，公网部署不要开启。`--insecure-skip-verify` 仅限受控测试环境。解析后 IP 校验挡住的是"解析结果是内网"的目标，不阻止对公网目标的正常访问。

### 七、构建与测试

```bash
go build -o proxyarea .
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
```

完整手工示例见 [test_usage.md](test_usage.md),配套上游:`go run ./examples/testserver -addr=:8081`。
