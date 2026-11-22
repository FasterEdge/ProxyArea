<div align="center">
  <img src="./Logo.png" alt="ProxyArea logo" width="100" />
  <h2>ProxyArea</h2>
  <h3>A Lightweight, Secure, Pure-Go REST-Compatible HTTP Forwarder</h3>
</div>

### 1. Introduction

ProxyArea is a lightweight REST-compatible HTTP forwarder in the FasterEdge ecosystem, implemented with the pure Go standard library. Current version `1.0.20261116`.

- Provides fixed routes `/get`, `/post`, `/put`, `/patch`, `/delete`, `/head`, `/options`, `/proxy`, `/healthz`; all routes and all methods preserve the business body byte-for-byte.
- Control fields come from query / explicit JSON envelope / form; the auth precedence is `Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form.
- The allowlist is matched case-insensitively and exactly against `URL.Hostname()`, and is re-validated on every redirect, with a default maximum of 10 hops.
- On top of the hostname allowlist, every DNS-**resolved IP** is validated by a single shared function used by the forward, redirect and CONNECT paths. Loopback / private / link-local / unspecified addresses and IPv4-mapped IPv6 bypasses are rejected, and the dial hook connects to the already-validated IP, closing the DNS-rebinding window.
- Passthrough request bodies and upstream response bodies are both capped (16 MiB / 64 MiB by default, tunable via `--max-request-body` and `--max-response-body`); exceeding a cap returns 413/502 or aborts the connection instead of returning a truncated "successful" response.

### 2. Getting Started

```bash
ProxyArea --addr=:8080 --key=my_secret --allow-hosts=127.0.0.1,api.internal
```

The existing CLI stays compatible: `--addr`, `--key`, `--https`, `--cert_file`, `--key_file`, `--timeout`, `--target-scheme`, `--allow-hosts`, `--insecure-skip-verify`.

Newly added flags (all have defaults, so existing invocations keep working):

| Flag | Default | Meaning |
|---|---|---|
| `--allow-private-nets` | `false` | Allow loopback/private/link-local targets; controlled networks and local tests only |
| `--max-request-body` | `16MiB` | Cap for passthrough (non-control) request bodies |
| `--max-response-body` | `64MiB` | Cap for upstream response bodies |

Size flags accept plain bytes or unit suffixes: `16MiB`, `64MB`, `1KiB`, `1B`.

### 3. Routes

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

### 4. Control Fields

`url` is required; `params` is parsed and merged into the target query string (duplicate keys are preserved and encoded only once); `https` accepts boolean values only and takes effect only when the URL has no scheme; `key` is used for compatible authentication.

The precedence for non-auth control fields is **query → explicit JSON envelope → form**. The auth precedence is **`Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form**. Once a higher-precedence source appears, it is not fallen back from even if empty or invalid.

Plain `application/json` is always the business body:

```bash
curl -X PATCH 'http://127.0.0.1:8080/proxy?url=http%3A%2F%2Fapi.internal%2Fitems%2F1' \
  -H 'Authorization: Bearer my_secret' -H 'Content-Type: application/json' \
  -d '{"name":"new"}'
```

urlencoded and multipart can carry `url`, `params`, `https`, `key`, and forward the original form (including control fields) completely. For business forms, it is recommended to put control fields in the query and auth in the Header.

#### Explicit JSON Envelope

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

### 5. URL, Headers and Errors

Only http/https are allowed; userinfo, control characters, missing hostnames and invalid ports are rejected. URLs without a scheme use `https=true` or `--target-scheme`. The allowlist is matched case-insensitively and exactly against `URL.Hostname()`, and is re-validated on every redirect, with a default maximum of 10 hops. On top of the hostname match, every hop also classifies the DNS answer; see section 6.

Both requests and responses strip the standard hop-by-hop headers and any headers dynamically specified by `Connection`; Host, Content-Length, Authorization, X-Proxy-Key are not forwarded. Multi-valued end-to-end headers (e.g. Set-Cookie) are preserved.

Error mapping: 400 control/URL errors, 401 auth failure, 403 allowlist or resolved-IP rejection, 404 unknown alias, 413 request body too large (control or passthrough), 502 upstream/redirect failure, DNS resolution failure, or response body too large, 504 timeout.

### 6. Security

ProxyArea can reach any target it is told to, so its boundary has **two** gates, and both matter:

**Gate 1: the target allowlist.** With `--allow-hosts` empty, any target is allowed (including private networks) and gate 1 is disabled. When configured, entries match `URL.Hostname()` case-insensitively, in two forms — `host` (any port) and `host:port` (exact host+port, so `/connect` cannot port-scan an allowlisted host) — and are re-matched on every redirect hop.

**Gate 2: resolved-IP validation.** The allowlist matches a *name*; where the connection actually lands depends on what DNS returns. So the forward, redirect and CONNECT paths all call one shared function (`validateTarget` → `checkResolvedIPs`), classify every resolved address, and reject the whole target if **any** address falls in a forbidden range — it never picks a "safe-looking" IP to connect to:

| Range | Meaning |
|---|---|
| `127.0.0.0/8`, `::1` | loopback |
| `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | private |
| `169.254.0.0/16`, `fe80::/10` | link-local (incl. cloud metadata `169.254.169.254`) |
| `100.64.0.0/10` | carrier-grade NAT |
| `0.0.0.0`, `::` | unspecified |
| multicast and reserved | same treatment |

IPv4-mapped IPv6 forms (`::ffff:10.0.0.1`) are normalized to IPv4 before classification; otherwise an IPv6-prefix check would miss them.

**DNS rebinding.** "Validate first, then let the HTTP client resolve again" still leaves a window: an attacker flips the DNS answer to an internal address between the two lookups. ProxyArea installs a dial hook on `Transport.DialContext` (`dialGuarded`) that uses **the same resolution result for validation and for the connection**, dialing the validated IP directly. If DNS changes after validation, the connection still goes to the address that was checked. The supplied Transport is cloned before the hook is installed, so the process-wide `http.DefaultTransport` is never mutated.

**Request and response body caps.** Non-control Content-Types used to stream their body through with no cap at all, which allows an unbounded upload to exhaust memory and bandwidth. Now:

| Cap | Default | CLI | On exceeding |
|---|---|---|---|
| Passthrough request body | 16 MiB | `--max-request-body` | known length → 413; chunked counted while reading → 413 |
| Upstream response body | 64 MiB | `--max-response-body` | known length → 502; chunked aborts the connection |
| Control body | 8 MiB | not configurable | 413 |

Exceeding a cap yields an explicit 413/502 or an aborted connection — **never** a truncated body returned as a success. The flags accept plain byte counts or unit suffixes such as `16MiB` / `64MB`.

**Deployment.** Authentication is off until `--key` is set, so public deployments must configure both `--key` and `--allow-hosts`. `--allow-private-nets` permits loopback/private/link-local targets for controlled networks and local tests only; do not enable it on a public deployment. `--insecure-skip-verify` is limited to controlled test environments. Resolved-IP validation blocks targets whose DNS answer is internal; it does not restrict access to legitimate public targets.

### 7. Build and Test

```bash
go build -o proxyarea .
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
```

For a complete manual example see [test_usage.md](test_usage.md); companion upstream: `go run ./examples/testserver -addr=:8081`.
