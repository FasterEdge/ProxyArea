# ProxyArea 手工测试

> 下列示例的目标都指向本机 `localhost`，会被「解析后 IP 校验」默认拒绝（`localhost` 解析到 `::1(回环)`），因此启动命令必须带 `--allow-private-nets`。该开关只放行回环/私网/链路本地；组播、未指定地址与保留段（如 `240.0.0.1`、`192.0.2.1`、`255.255.255.255`）即使开启也仍然拒绝。

启动上游与代理：

```bash
go run ./examples/testserver -addr=:8081
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=127.0.0.1,localhost --allow-private-nets
```

## 固定与通用路由

```bash
curl -H 'Authorization: Bearer my_secret' 'http://localhost:8080/get?url=http%3A%2F%2Flocalhost%3A8081%2Ftest%2Fget'
curl -X POST -H 'X-Proxy-Key: my_secret' 'http://localhost:8080/post?url=http%3A%2F%2Flocalhost%3A8081%2Ftest%2Fpost' -d 'raw body'
curl -X PROPFIND -H 'X-Proxy-Key: my_secret' 'http://localhost:8080/proxy?url=http%3A%2F%2Flocalhost%3A8081%2Ftest%2Fall' -d 'propfind body'
curl -X OPTIONS -H 'X-Proxy-Key: my_secret' 'http://localhost:8080/proxy/?url=http%3A%2F%2Flocalhost%3A8081%2Ftest%2Fall' -d 'options body'
```

七个方法别名（客户端方法不影响别名指定的上游方法）：

```bash
for alias in get post put patch delete head options; do
  curl -X GET -H 'X-Proxy-Key: my_secret' \
    "http://localhost:8080/proxy/$alias?url=http%3A%2F%2Flocalhost%3A8081%2Ftest%2Fall" -d "body-$alias"
done
```

`/proxy/nope` 应返回 404。

`/connect` 隧道端点（认证与目标校验与 forward 一致；缺凭据 401，目标被拒 403，白名单条目写成 `host:port` 才能限制端口）：

```bash
curl -v -H 'X-Proxy-Key: my_secret' \
  'http://localhost:8080/connect?url=http%3A%2F%2Flocalhost%3A8081'
```

`-v` 会看到 `HTTP/1.1 200 Connection Established`，随后连接被当作裸 TCP 隧道使用（测试服务器说的是 HTTP，因此会立即收到 400 之类的解析失败，这属于预期）。

## JSON、表单、multipart

普通 JSON 是业务 body：

```bash
curl -X PATCH 'http://localhost:8080/proxy?url=http%3A%2F%2Flocalhost%3A8081%2Ftest%2Fall' \
  -H 'Authorization: Bearer my_secret' -H 'Content-Type: application/json' -d '{"url":"business-value"}'
```

表单中的控制字段会被读取，但原始表单仍完整转发：

```bash
curl -X POST http://localhost:8080/proxy -H 'X-Proxy-Key: my_secret' \
  -d 'url=http://localhost:8081/test/all' -d 'name=alice'
```

业务 multipart 推荐控制字段放 query/header：

```bash
curl -X POST 'http://localhost:8080/proxy?url=http%3A%2F%2Flocalhost%3A8081%2Ftest%2Fall' \
  -H 'X-Proxy-Key: my_secret' -F 'file=@README.md' -F 'note=kept'
```

## 显式 envelope

```bash
curl -X POST http://localhost:8080/proxy \
  -H 'Content-Type: application/vnd.proxyarea.proxy+json' \
  -H 'Authorization: Bearer my_secret' \
  -d '{"url":"http://localhost:8081/test/all","encoding":"json","body":{"hello":"world"},"contentType":"application/json"}'

curl -X POST http://localhost:8080/proxy \
  -H 'Content-Type: application/vnd.proxyarea.proxy+json' -H 'X-Proxy-Key: my_secret' \
  -d '{"url":"http://localhost:8081/test/all","encoding":"base64","body":"AAH/","contentType":"application/octet-stream"}'
```

`encoding` 还支持 `text`（body 为 JSON 字符串）与 `none`（不带 body）。未知字段、非法 base64、额外 JSON 值应返回 400，超过 8 MiB 返回 413。

## 优先级与错误

- `Authorization` 出现时优先于 `X-Proxy-Key` 和其他 key；空值或错误值返回 401，不回退。
- `X-Proxy-Key` 出现时优先于 query/envelope/form key。
- query 中出现的控制字段优先于 envelope/form，即使为空。
- **直接请求** 非白名单主机、或目标解析到被拒网段 → `403`。
- **重定向的下一跳** 非白名单主机、或解析到被拒网段 → `502`（错误体里写着 `上游请求失败: ... 目标主机不在白名单内`）。重定向逐跳校验在 `CheckRedirect` 里做，错误只能经 `client.Do` 冒泡，统一按「上游/重定向失败」映射为 502。
- 上游连接失败返回 502，超时返回 504。
- 控制类 body（urlencoded/multipart 字段数 > 1024，或 body 超过 8 MiB）返回 413。

实测样例（本地 `--key=my_secret`；保留段那条需先启动 `ProxyArea --addr=:8080 --key=my_secret --allow-private-nets`，即**不配** `--allow-hosts`，否则白名单会先于 IP 分类给出「不在白名单内」）：

```bash
# 直接请求非白名单主机 → 403
curl -s -w ' %{http_code}\n' -H 'Authorization: Bearer my_secret' \
  'http://localhost:8080/get?url=http%3A%2F%2Fexample.com%2F'
# {"error":"目标主机不在白名单内: example.com"} 403

# 保留段目标 → 403（--allow-private-nets 也放不出来）
curl -s -w ' %{http_code}\n' -H 'Authorization: Bearer my_secret' \
  'http://localhost:8080/get?url=http%3A%2F%2F240.0.0.1%2Fx'
# {"error":"目标主机 240.0.0.1 解析到 240.0.0.1(保留段), 拒绝访问: 目标被安全策略拒绝"} 403

# 上游 302 跳到非白名单主机 → 502
curl -s -w ' %{http_code}\n' -H 'Authorization: Bearer my_secret' \
  'http://localhost:8080/get?url=http%3A%2F%2Flocalhost%3A8081%2Fredirect%3Fto%3Dhttp%253A%252F%252Fexample.com%252F'
# {"error":"上游请求失败: Get \"http://example.com/\": 目标主机不在白名单内: example.com"} 502
```

测试服务器会回显 method、path、query、Header、原始 body 文本与 base64，并提供 `/redirect?to=...`、`/delay?duration=100ms` 和 `/headers` 测试端点。
