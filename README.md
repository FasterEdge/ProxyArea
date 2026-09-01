# ProxyArea

轻量、纯 Go 标准库实现的 REST 兼容 HTTP 转发器。当前版本 `1.0.20260901`。

## 启动

```bash
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=127.0.0.1,api.internal
```

现有 CLI 保持兼容：`--addr`、`--key`、`--https`、`--cert_file`、`--key_file`、`--timeout`、`--target-scheme`、`--allow-hosts`、`--insecure-skip-verify`。

## 路由

| 路径 | 上游方法 |
|---|---|
| `/get` | GET |
| `/post` | POST |
| `/put` | PUT |
| `/patch` | PATCH |
| `/delete` | DELETE |
| `/head` | HEAD |
| `/options` | OPTIONS |
| `/proxy` | 客户端原方法，包括 PROPFIND 等扩展方法 |
| `/healthz` | 健康检查（返回 200 OK） |

未知或更深的 `/proxy/...` 返回 404。所有路由、所有方法都会按字节保留业务 body，包括 GET、HEAD、OPTIONS 和 DELETE；没有 body 时不会自动添加 Content-Type。

## 控制字段

`url` 必填；`params` 会解析后合并到目标 query（重复键保留且只编码一次）；`https` 仅接受布尔值并仅在 URL 无协议时生效；`key` 用于兼容认证。

非认证控制字段优先级为 **query → 显式 JSON envelope → form**。认证优先级为 **`Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form**。高优先级来源一旦出现，即使为空或错误也不会回退。

普通 `application/json` 永远是业务 body：

```bash
curl -X PATCH 'http://127.0.0.1:8080/proxy?url=http%3A%2F%2Fapi.internal%2Fitems%2F1' \
  -H 'Authorization: Bearer my_secret' -H 'Content-Type: application/json' \
  -d '{"name":"new"}'
```

urlencoded 与 multipart 可携带 `url`、`params`、`https`、`key`，并会把原始表单（包括控制字段）完整转发。业务表单推荐把控制字段放 query、认证放 Header。

### 显式 JSON envelope

媒体类型：`application/vnd.proxyarea.proxy+json`。

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

`encoding` 支持：`none`（默认且不得带 body）、`json`、`text`、`base64`。未知字段、额外 JSON 值、无效编码/base64/contentType 均返回 400；控制 body 上限 8 MiB，超限返回 413。

## URL、Header 与错误

仅允许 http/https，拒绝 userinfo、控制字符、缺少 hostname 和非法端口。无协议 URL 使用 `https=true` 或 `--target-scheme`。白名单按 `URL.Hostname()` 大小写无关精确匹配，并在每次重定向重新验证，默认最多 10 跳。

请求和响应都移除标准 hop-by-hop Header 及 `Connection` 动态指定的 Header；不转发 Host、Content-Length、Authorization、X-Proxy-Key。多值端到端 Header（例如 Set-Cookie）保留。

错误映射：400 控制/URL 错误，401 认证失败，403 白名单拒绝，404 未知别名，413 控制 body 超限，502 上游或重定向失败，504 超时。

## 安全

未配置 `--key` 时认证关闭；`--allow-hosts` 为空时允许任意目标（包括私网）。公网部署必须同时配置两者，并在部署层限制出口。`--insecure-skip-verify` 仅限受控测试环境。

## 构建与测试

```bash
go build -o proxyarea .
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
```

完整手工示例见 [test_usage.md](test_usage.md)，配套上游：`go run ./examples/testserver -addr=:8081`。
