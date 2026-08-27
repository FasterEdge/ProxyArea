# ProxyArea 手工测试

启动上游与代理：

```bash
go run ./examples/testserver -addr=:8081
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=127.0.0.1,localhost
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
- 非白名单主机及重定向到非白名单主机分别返回 403 和 502。
- 上游连接失败返回 502，超时返回 504。

测试服务器会回显 method、path、query、Header、原始 body 文本与 base64，并提供 `/redirect?to=...`、`/delay?duration=100ms` 和 `/headers` 测试端点。
