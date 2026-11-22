<div align="center">
  <img src="./Logo.png" alt="ProxyArea logo" width="100" />
  <h2>ProxyArea</h2>
  <h3>轻量、安全、纯 Go 标准库实现的 REST 兼容 HTTP 转发器</h3>
</div>

### 一、项目简介

ProxyArea 是 FasterEdge 生态中的轻量级 REST 兼容 HTTP 转发器,纯 Go 标准库实现,当前版本 `1.0.20261123`。

- 提供 `/get`、`/post`、`/put`、`/patch`、`/delete`、`/head`、`/options`、`/proxy`、`/healthz` 等固定路由,所有路由、所有方法按字节保留业务 body。
- 控制字段来源 query / 显式 JSON envelope / form,认证优先级 `Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form。
- 白名单按 `URL.Hostname()` 大小写无关精确匹配,并在每次重定向重新验证,默认最多 10 跳。
- 除了主机名白名单,还对**DNS 解析后的 IP** 做统一校验:forward、重定向、CONNECT 三条路径共用同一函数,拒绝回环/私网/链路本地/未指定地址/组播/保留段(含 240.0.0.0/4、198.18.0.0/15、TEST-NET-1/2/3、255.255.255.255 及内嵌 IPv4 的 NAT64/6to4/Teredo)及 IPv4-mapped IPv6 绕过,并在拨号阶段按已校验的 IP 连接以关闭 DNS rebinding 窗口。
- 非控制类(透传)请求体与上游响应体都有上限(默认 16 MiB / 64 MiB,可用 `--max-request-body`、`--max-response-body` 调整),超限返回 413/502 或中断连接,不返回被截断的"成功"响应。

### 二、启动

公网部署（目标为公网域名，不放开私网）：

```bash
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=api.example.com --require-allowlist
```

本地测试 / 受控内网（目标在本机或内网）：

```bash
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=127.0.0.1,localhost --allow-private-nets
```

`--allow-private-nets` 只应加在**本地测试 / 受控内网**场景：它放行回环/私网/链路本地目标（组播、未指定地址与保留段即使开启也不放行）。公网部署不要加。

> **为什么默认拒绝回环？** 第二道防线（第六节）按 DNS 解析结果分类目标，`127.0.0.0/8`、`::1` 属于"解析后 IP 校验"默认拒绝的类别。因此把 `--allow-hosts=127.0.0.1,localhost` 配上去访问 `http://localhost:8081` 会被 403 拒绝——主机名白名单只回答"这个主机名是否被允许"，并不豁免 IP 分类。实测响应为 `{"error":"目标主机 localhost 解析到 ::1(回环), 拒绝访问: 目标被安全策略拒绝"}`。要打通本地链路必须追加 `--allow-private-nets`。

现有 CLI 保持兼容:`--addr`、`--key`、`--https`、`--cert_file`、`--key_file`、`--timeout`、`--target-scheme`、`--allow-hosts`、`--insecure-skip-verify`。

安全相关 CLI:`--require-allowlist`(要求 `--allow-hosts` 至少配一个目标,否则启动失败)、`--max-redirects`(最大重定向次数,0 表示用默认 10)、`--disable-redirects`(不跟随上游重定向,直接返回上游响应)。

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
| `/proxy/` | 同 `/proxy`(末尾带斜杠的写法) |
| `/proxy/{get,post,put,patch,delete,head,options}` | 别名: 忽略客户端方法,固定用别名指定的上游方法 |
| `/connect` | 建立 TCP 隧道(用于 HTTPS、WebSocket 等),认证与目标校验与 forward 一致 |
| `/healthz` | 健康检查(返回 200 OK) |

未知或更深的 `/proxy/...` 返回 404。所有路由、所有方法都会按字节保留业务 body,包括 GET、HEAD、OPTIONS 和 DELETE;没有 body 时不会自动添加 Content-Type。

`/connect` 与其它路由一样要过认证和两道安全关:配置 `--key` 后未带凭据返回 401;目标不在白名单或解析到被拒网段时,按 `statusForTargetError` 返回 403(策略拒绝)或 502(解析失败)。白名单条目写成 `host:port` 形式可防止对同一主机的任意端口建隧道。

### 四、控制字段

`url` 必填;`params` 会解析后合并到目标 query(重复键保留且只编码一次);`https` 仅接受布尔值并仅在 URL 无协议时生效;`key` 用于兼容认证。

非认证控制字段优先级为 **query → 显式 JSON envelope → form**。认证优先级为 **`Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form**。高优先级来源一旦出现,即使为空或错误也不会回退。

普通 `application/json` 永远是业务 body:

```bash
curl -X PATCH 'http://127.0.0.1:8080/proxy?url=http%3A%2F%2Fapi.example.com%2Fitems%2F1' \
  -H 'Authorization: Bearer my_secret' -H 'Content-Type: application/json' \
  -d '{"name":"new"}'
```

urlencoded 与 multipart 可携带 `url`、`params`、`https`、`key`,并会把原始表单(包括控制字段)完整转发。业务表单推荐把控制字段放 query、认证放 Header。

表单字段数上限为 **1024**（`controls.go:maxFormFields`，不可配置）：urlencoded 的键数量或 multipart 的 part 数量超过 1024 时返回 413（实测 1024 个字段 → 200，1025 个 → 413 `control body too large`），用于避免海量字段造成的解析开销。

#### 显式 JSON envelope

媒体类型:`application/vnd.proxyarea.proxy+json`。

```json
{
  "url": "https://api.example.com/items",
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

**来源头改写。** 客户端自带的 `X-Forwarded-For`、`Forwarded`、`X-Real-IP` 会被**删除**，然后按 TCP 对端地址重新写入 `X-Forwarded-For`（取不到对端主机时就不写）。这样上游基于这些头做的来源鉴权无法被客户端伪造。若 envelope 替换了 body，会额外删除 `Content-Encoding`。

错误映射:400 控制/URL 错误,401 认证失败,403 白名单或解析后 IP 校验拒绝,404 未知别名,413 请求体(控制类或透传)超限,502 上游/重定向失败、DNS 解析失败或响应体超限,504 超时。

**403 与 502 的边界。** 同一个"策略拒绝"在两条路径上状态码不同，必须分开理解：

| 场景 | 状态码 | 实测响应 |
|---|---|---|
| 直接请求的目标不在白名单 / 解析到被拒网段 | `403` | `{"error":"目标主机 127.0.0.1 解析到 127.0.0.1(回环), 拒绝访问: 目标被安全策略拒绝"}` |
| **重定向**的下一跳不在白名单 / 解析到被拒网段 | `502` | `{"error":"上游请求失败: Get \"http://example.com/\": 目标主机不在白名单内: example.com"}` |

原因是重定向的逐跳校验发生在 `http.Client.CheckRedirect` 里（`proxy.go:103-107`），错误只能经 `client.Do` 冒泡回 `forward`，而 `forward` 对 `Do` 返回的所有错误统一映射为 502（「上游或重定向失败」）。502 响应体里的 `上游请求失败: Get "...": 目标主机不在白名单内` 才是区分原因的依据。`/connect` 隧道端点不走 `client.Do`，策略拒绝直接是 403。

### 六、安全

ProxyArea 是一个可访问任意目标的转发器，因此安全边界必须同时看**白名单**和**解析后 IP**两道关：

**第一道：目标白名单。** `--allow-hosts` 为空时允许任意目标（包括私网），此时唯一防线是第二道。配置后按 `URL.Hostname()` 大小写无关精确匹配，条目支持 `host`（不限端口）与 `host:port`（精确匹配主机+端口，防止 `/connect` 对白名单主机做任意端口扫描）两种形式；每一跳重定向都会重新匹配。

**第二道：解析后 IP 校验。** 白名单匹配的是主机名，而 `buildTargetURL` 之后真正连到哪里，取决于 DNS 返回什么。因此 forward、重定向、CONNECT 三条路径共用同一个校验函数（`proxy.go:validateTarget` → `netguard.go:checkResolvedIPs`），把 DNS 解析结果逐一分类，命中以下网段即整体拒绝——只要有一个解析结果是内网地址，整个目标就被拒绝，不会挑一个"看起来安全"的 IP 来连：

| 网段 | 说明 | 可被 `--allow-private-nets` 放行 |
|---|---|---|
| `127.0.0.0/8`、`::1` | 回环 | 是 |
| `10/8`、`172.16/12`、`192.168/16`、`fc00::/7` | 私网 | 是 |
| `169.254.0.0/16`、`fe80::/10` | 链路本地（含云元数据 `169.254.169.254`） | 是 |
| `100.64.0.0/10` | 运营商级 NAT | 是 |
| `0.0.0.0`、`::` | 未指定地址 | 否 |
| `224.0.0.0/4`、`ff00::/8` | 组播 | 否 |
| `240.0.0.0/4` | 保留段，含受限广播 `255.255.255.255/32` | 否 |
| `198.18.0.0/15` | 基准测试（RFC 2544） | 否 |
| `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24` | TEST-NET-1/2/3 文档段（RFC 5737） | 否 |
| `2001:db8::/32`、`3fff::/20` | IPv6 文档段 | 否 |
| `2001:2::/48` | IPv6 基准测试 | 否 |
| `100::/64` | IPv6 丢弃段（RFC 6666） | 否 |
| `64:ff9b::/96`、`64:ff9b:1::/48` | NAT64 前缀（RFC 6052/8215），可内嵌任意 IPv4 | 否 |
| `2002::/16`、`2001::/32` | 6to4 / Teredo，可内嵌任意 IPv4 | 否 |

保留段/基准测试段/文档段/受限广播与 NAT64、6to4、Teredo 这类"内嵌 IPv4"的 IPv6 前缀，标准库的 `net.IP.IsPrivate/IsMulticast/IsLinkLocalUnicast` 都不判定。实测（见第七节）`240.0.0.1`、`198.18.0.1`、`255.255.255.255`、`192.0.2.1`、`198.51.100.1`、`203.0.113.1`、`2001:db8::1` 与 `::ffff:240.0.0.1` 在修复前全部被判为公网放行，修复后统一返回 403 并标注「保留段」。这些网段**恒被拒绝**，`--allow-private-nets` 对它们无效——否则该开关会变成任意地址打洞器。

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

本机实测（go1.27.4 / windows/amd64，2026-11-23）：`gofmt -l` 无输出，`go vet ./...` 通过，`go test ./...` 通过（107 个用例）。保留段判定由 `TestClassifyIPBlocksReservedRanges`、`TestClassifyIPNormalizesIPv4Mapped`、`TestPrivateTargetRejectedOnAllPaths`（forward 与 CONNECT 两条路径）、`TestRedirectHopRechecksResolvedIP`（逐跳重定向）与 `TestAllowPrivateNetsDoesNotOpenReservedRanges` 覆盖。
