# 安全政策

## 支持的版本

| 版本 | 支持状态 |
| ---- | -------- |
| main (开发分支) | ✅ 支持 |

## 安全边界

ProxyArea 是一个"按请求转发到任意目标"的组件，它的安全性完全来自下面四层控制。部署前请确认每一层的取值，任何一层被放宽都意味着边界被放宽。

### 1. 认证（`--key`）

- `--key` 为空时**认证关闭**，任何人都能通过本服务发起转发，公网部署必须先设 `--key`。
- 配置后凭据来源优先级固定为 `Authorization: Bearer` → `X-Proxy-Key` → query → envelope → form；高优先级来源一旦出现，即使为空或错误也不回退，直接 401。
- 凭据比较使用 `crypto/subtle.ConstantTimeCompare`，长度不同即失败，不泄露前缀。
- **所有路由都校验凭据**，包括 `/connect`（历史版本曾跳过，等于配置了 key 也能免鉴权建内网 TCP 隧道，现已修复）与 `/proxy/*` 别名。

### 2. 目标白名单（`--allow-hosts` / `--require-allowlist`）

- `--allow-hosts` 为空时不限制主机名，此层的防护完全消失。`--require-allowlist` 让进程在未配置白名单时**启动失败**，公网部署建议同时使用。
- 匹配对象是 `URL.Hostname()`，大小写无关、精确匹配（不做后缀/通配匹配），两种条目形式：
  - `host`：只约束主机名，不限端口；
  - `host:port`：精确匹配主机+端口。转发器同时提供 `/connect` TCP 隧道，只有这种形式才能阻止对白名单主机的**任意端口扫描**。
- 每一跳重定向都重新匹配白名单。

### 3. 解析后 IP 校验（`--allow-private-nets`）

白名单匹配的是主机名，真正连到哪里由 DNS 决定。因此 forward、重定向、CONNECT 三条路径共用同一函数 `netguard.go:checkResolvedIPs`，对每条解析结果分类，**任一结果落在被拒网段即整体拒绝**（不会挑一个"看起来安全"的 IP 来连）。

| 网段 | 类别 | `--allow-private-nets` 可放行 |
|---|---|---|
| `127.0.0.0/8`、`::1` | 回环 | 是 |
| `10/8`、`172.16/12`、`192.168/16`、`fc00::/7` | 私网 | 是 |
| `169.254.0.0/16`、`fe80::/10` | 链路本地（含云元数据 `169.254.169.254`） | 是 |
| `100.64.0.0/10` | 运营商级 NAT | 是 |
| `0.0.0.0`、`::` | 未指定地址 | 否 |
| `224.0.0.0/4`、`ff00::/8` | 组播 | 否 |
| `240.0.0.0/4`（含 `255.255.255.255/32`） | 保留段 | 否 |
| `198.18.0.0/15` | 基准测试（RFC 2544） | 否 |
| `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24` | TEST-NET-1/2/3（RFC 5737） | 否 |
| `2001:db8::/32`、`3fff::/20`、`2001:2::/48` | IPv6 文档段/基准测试 | 否 |
| `100::/64` | IPv6 丢弃段（RFC 6666） | 否 |
| `64:ff9b::/96`、`64:ff9b:1::/48` | NAT64（可内嵌任意 IPv4） | 否 |
| `2002::/16`、`2001::/32` | 6to4 / Teredo（可内嵌任意 IPv4） | 否 |

- `--allow-private-nets` 的语义**恰好是上表前三行加 CGNAT**：只放行回环/私网/链路本地。组播、未指定地址、保留段、基准测试段、文档段与内嵌 IPv4 的 IPv6 前缀**恒被拒绝**，该开关放不了它们。
- IPv4-mapped IPv6（`::ffff:a.b.c.d`）先归一化为 IPv4 再分类，否则按 IPv6 前缀判定会被绕过。
- 默认（`--allow-private-nets=false`）拒绝回环，意味着本机 `localhost` / `127.0.0.1` 目标会被 403 拒绝；这是有意的默认值，本地测试需显式加开关。

### 4. DNS rebinding 与拨号

"先校验、再让 HTTP 客户端自己解析"仍留有 TOCTOU 窗口。`netguard.go:dialGuarded` 装在 `Transport.DialContext` 上，**解析、校验、连接共用同一份结果**，直接连接校验过的 IP；Transport 是克隆后再装的钩子，不会污染进程全局 `http.DefaultTransport`。

### 5. 体积上限与请求面

| 上限 | 默认 | 是否可配 | 超限 |
|---|---|---|---|
| 控制类 body | 8 MiB | 否 | 413 |
| 表单字段数 | 1024（`controls.go:maxFormFields`） | 否 | 413 |
| 透传请求体 | 16 MiB | `--max-request-body` | 已知长度 413；chunked 边读边计数，413 |
| 上游响应体 | 64 MiB | `--max-response-body` | 已知长度 502；chunked 中断连接 |

超限一律返回明确错误或中断连接，绝不把截断内容当成成功响应返回。

**Header 与来源。** 请求和响应都剥离标准 hop-by-hop 头及 `Connection` 指定的头；`Host`、`Content-Length`、`Authorization`、`X-Proxy-Key` 不转发。客户端自带的 `X-Forwarded-For`、`Forwarded`、`X-Real-IP` 会被删除，`X-Forwarded-For` 按真实 TCP 对端重写，因此上游不能信任客户端伪造的来源头。

**重定向。** 默认最多 10 跳（`--max-redirects` 可改，`--disable-redirects` 可完全关闭跟随），每跳重新白名单+IP 校验，并剥离 `Authorization`/`X-Proxy-Key`，避免跨主机重定向泄露凭据。

**本机部署。** 服务本身不提供 TLS 客户端防护以外的隔离；`--insecure-skip-verify` 仅限受控测试环境，它会关闭上游证书校验。公网部署应置于反向代理之后并**不要**开启 `--allow-private-nets`。

## 报告安全漏洞

FasterEdge 项目重视安全。请**不要在公共渠道（Issue/讨论区/群聊）公开未修复的漏洞细节**。

请通过以下渠道私密报告：

- **GitHub Security Advisory**（推荐）：在本仓库的 *Security* → *Report a vulnerability* 提交，或直接访问
  `https://github.com/FasterEdge/ProxyArea/security/advisories/new`
- **邮件**：`shun_@outlook.com`（主题请注明 `[FasterEdge Security]`）

### 报告中请包含

1. 漏洞类型与影响组件
2. 触发条件与复现步骤（尽量精简）
3. 影响范围（可读性 / 可用性 / 安全性）
4. 触发时使用的启动参数（尤其是 `--allow-hosts`、`--allow-private-nets`、`--key` 是否设置）

### 响应承诺

- **48 小时内**：确认收到报告并评估严重性
- **7 天内**：给出修复计划或缓解措施
- **修复发版后**：在致谢中列入报告者（如同意）

## 致谢

我们感谢所有以负责任方式报告问题的安全研究人员。
