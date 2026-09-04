# ProxyArea

A lightweight REST-compatible HTTP forwarder implemented with the pure Go standard library. Current version `1.0.20260902`.

## Getting Started

```bash
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=127.0.0.1,api.internal
```

The existing CLI stays compatible: `--addr`, `--key`, `--https`, `--cert_file`, `--key_file`, `--timeout`, `--target-scheme`, `--allow-hosts`, `--insecure-skip-verify`.

## Routes

| Path | Upstream Method |
|---|---|
| `/get` | GET |
| `/post` | POST |
| `/put` | PUT |
| `/patch` | PATCH |
| `/delete` | DELETE |
| `/head` | HEAD |
| `/options` | OPTIONS |
| `/proxy` | The client's original method, including extension methods such as PROPFIND |
| `/healthz` | Health check (returns 200 OK) |

Unknown or deeper `/proxy/...` paths return 404. All routes and all methods preserve the business body byte-for-byte, including GET, HEAD, OPTIONS and DELETE; no Content-Type is added automatically when there is no body.

## Control Fields

`url` is required; `params` is parsed and merged into the target query string (duplicate keys are preserved and encoded only once); `https` accepts boolean values only and takes effect only when the URL has no scheme; `key` is used for compatible authentication.

The precedence for non-auth control fields is **query → explicit JSON envelope → form**. The auth precedence is **`Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form**. Once a higher-precedence source appears, it is not fallen back from even if empty or invalid.

Plain `application/json` is always the business body:

```bash
curl -X PATCH 'http://127.0.0.1:8080/proxy?url=http%3A%2F%2Fapi.internal%2Fitems%2F1' \
  -H 'Authorization: Bearer my_secret' -H 'Content-Type: application/json' \
  -d '{"name":"new"}'
```

urlencoded and multipart can carry `url`, `params`, `https`, `key`, and forward the original form (including control fields) completely. For business forms, it is recommended to put control fields in the query and auth in the Header.

### Explicit JSON Envelope

Media type: `application/vnd.proxyarea.proxy+json`.

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

`encoding` supports: `none` (default, must not carry a body), `json`, `text`, `base64`. Unknown fields, extra JSON values, invalid encoding/base64/contentType all return 400; the control body limit is 8 MiB, exceeding it returns 413.

## URL, Headers and Errors

Only http/https are allowed; userinfo, control characters, missing hostnames and invalid ports are rejected. URLs without a scheme use `https=true` or `--target-scheme`. The allowlist is matched case-insensitively and exactly against `URL.Hostname()`, and is re-validated on every redirect, with a default maximum of 10 hops.

Both requests and responses strip the standard hop-by-hop headers and any headers dynamically specified by `Connection`; Host, Content-Length, Authorization, X-Proxy-Key are not forwarded. Multi-valued end-to-end headers (e.g. Set-Cookie) are preserved.

Error mapping: 400 control/URL errors, 401 auth failure, 403 allowlist rejection, 404 unknown alias, 413 control body too large, 502 upstream or redirect failure, 504 timeout.

## Security

When `--key` is not configured, authentication is disabled; when `--allow-hosts` is empty, any target (including private networks) is allowed. Public deployments must configure both, and restrict egress at the deployment layer. `--insecure-skip-verify` is limited to controlled test environments.

## Build and Test

```bash
go build -o proxyarea .
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
```

For a complete manual example see [test_usage.md](test_usage.md); companion upstream: `go run ./examples/testserver -addr=:8081`.