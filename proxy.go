// ─────────────────────────────────────────────────────────────
// FasterEdge 开源项目
// Github: https://github.com/FasterEdge
// Gitee:  https://gitee.com/FasterEdge
// ─────────────────────────────────────────────────────────────
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Key                string
	DefaultScheme      string
	AllowHosts         []string
	RequireAllowlist   bool
	Timeout            time.Duration
	InsecureSkipVerify bool
	Transport          http.RoundTripper
	MaxRedirects       int
	DisableRedirects   bool

	// MaxRequestBody 是非控制类(透传)请求体上限, 默认 DefaultMaxRequestBody。
	// 控制类请求体另有 maxControlBody 上限, 两者取小者生效。
	MaxRequestBody int64
	// MaxResponseBody 是上游响应体上限, 默认 DefaultMaxResponseBody。
	MaxResponseBody int64
	// AllowPrivateNets 放行回环/私网/链路本地地址, 仅供受控内网与测试使用。
	AllowPrivateNets bool
	// LookupIP 替换默认解析器, 用于测试注入(例如模拟 DNS rebinding)。
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

const (
	// DefaultMaxRequestBody 16 MiB: 覆盖常规 JSON/表单业务体, 同时挡住无限流式上传。
	DefaultMaxRequestBody int64 = 16 << 20
	// DefaultMaxResponseBody 64 MiB: 兼顾大文件下载与内存/带宽可预期性。
	DefaultMaxResponseBody int64 = 64 << 20
)

type Proxy struct {
	cfg    Config
	client *http.Client
}

func NewProxy(cfg Config) (*Proxy, error) {
	if cfg.DefaultScheme == "" {
		cfg.DefaultScheme = "http"
	}
	if cfg.DefaultScheme != "http" && cfg.DefaultScheme != "https" {
		return nil, errors.New("target-scheme must be http or https")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRedirects < 0 {
		return nil, errors.New("max redirects must be non-negative")
	}
	if cfg.RequireAllowlist && len(cfg.AllowHosts) == 0 {
		return nil, errors.New("allow-hosts is required when safe allowlist mode is enabled")
	}
	if cfg.MaxRequestBody <= 0 {
		cfg.MaxRequestBody = DefaultMaxRequestBody
	}
	if cfg.MaxResponseBody <= 0 {
		cfg.MaxResponseBody = DefaultMaxResponseBody
	}
	if cfg.Transport == nil {
		cfg.Transport = http.DefaultTransport
	}
	p := &Proxy{cfg: cfg}
	// 在传输层装上"解析→校验→按校验结果拨号"的钩子, 关闭 DNS rebinding 的
	// TOCTOU 窗口。必须克隆 *http.Transport: 直接改传入的 Transport(常见是
	// http.DefaultTransport)会污染进程全局状态。
	if base, ok := cfg.Transport.(*http.Transport); ok {
		tr := base.Clone()
		tr.DialContext = p.dialGuarded
		cfg.Transport = tr
		p.cfg.Transport = tr
	}
	p.client = &http.Client{Timeout: cfg.Timeout, Transport: cfg.Transport}
	p.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if cfg.DisableRedirects {
			return http.ErrUseLastResponse
		}
		limit := cfg.MaxRedirects
		if limit == 0 {
			limit = 10
		}
		if len(via) >= limit {
			return errors.New("too many redirects")
		}
		if _, err := p.validateTarget(req.Context(), req.URL); err != nil {
			// 错误会经 client.Do 冒泡到 forward, 按既有文档映射为 502
			//(「上游或重定向失败」), 与原有的重定向白名单拒绝行为保持一致。
			return err
		}
		req.Header.Del("Authorization")
		req.Header.Del("X-Proxy-Key")
		return nil
	}
	return p, nil
}

func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	// 根路径返回提示信息
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, rootMsg)
	})

	// 健康检查路由
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// 完整的 HTTP 方法路由
	mux.HandleFunc("/get", p.route(http.MethodGet))
	mux.HandleFunc("/post", p.route(http.MethodPost))
	mux.HandleFunc("/put", p.route(http.MethodPut))
	mux.HandleFunc("/patch", p.route(http.MethodPatch))
	mux.HandleFunc("/delete", p.route(http.MethodDelete))
	mux.HandleFunc("/head", p.route(http.MethodHead))
	mux.HandleFunc("/options", p.route(http.MethodOptions))

	// CONNECT 隧道（用于 HTTPS、WebSocket 等）
	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		c, err := parseControls(r.Body, r.Header.Get("Content-Type"), r.URL.Query())
		if err != nil {
			writeJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		// 认证绕过修复: 旧实现 /connect 跳过 key 校验, 配置 --key 后仍可免鉴权
		// 建立内网 TCP 隧道; 现与 forward 一致校验凭据。
		if !p.authorize(r, c) {
			writeJSON(w, http.StatusUnauthorized, "invalid key")
			return
		}
		target, err := buildTargetURL(c, p.cfg.DefaultScheme)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err = p.validateTarget(r.Context(), target); err != nil {
			writeJSON(w, statusForTargetError(err), err.Error())
			return
		}

		// Hijack 客户端连接
		hj, ok := w.(http.Hijacker)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, "Hijacking not supported")
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer clientConn.Close()

		// 建立到目标的 TCP 连接: 复用 dialGuarded, 按已校验的 IP 拨号,
		// 与 forward/重定向共用同一份校验实现。
		upstream, err := p.dialGuarded(r.Context(), "tcp", target.Host)
		if err != nil {
			writeJSON(w, statusForTargetError(err), err.Error())
			return
		}
		defer upstream.Close()

		// 响应 CONNECT 成功
		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// 双向流量转发
		go func() { _, _ = io.Copy(upstream, clientConn) }()
		_, _ = io.Copy(clientConn, upstream)
	})

	// 保持原有的通用 /proxy 路由（支持任意方法）
	mux.HandleFunc("/proxy", p.route(""))
	// 兼容旧式 /proxy/* 别名（例如 /proxy/get、/proxy/post 等）
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		aliases := map[string]string{"/proxy/get": http.MethodGet, "/proxy/post": http.MethodPost, "/proxy/put": http.MethodPut, "/proxy/patch": http.MethodPatch, "/proxy/delete": http.MethodDelete, "/proxy/head": http.MethodHead, "/proxy/options": http.MethodOptions}
		if r.URL.Path == "/proxy/" {
			p.forward(w, r, r.Method)
			return
		}
		method, ok := aliases[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		p.forward(w, r, method)
	})
	return mux
}
func (p *Proxy) route(method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestMethod := method
		if requestMethod == "" {
			requestMethod = r.Method
		}
		p.forward(w, r, requestMethod)
	}
}

// authorize 校验请求凭据(c.key 或 Authorization/X-Proxy-Key 头)。
// 未配置 Key 时放行; 配置时用常数时间比较。旧实现仅 forward 校验, /connect
// 隧道端点完全跳过认证 → 配置 --key 后仍可免鉴权建立内网 TCP 隧道(认证绕过)。
func (p *Proxy) authorize(r *http.Request, c controls) bool {
	if p.cfg.Key == "" {
		return true
	}
	credential := c.key
	if vals, ok := r.Header["Authorization"]; ok {
		credential = value{present: true}
		if len(vals) > 0 && strings.HasPrefix(vals[0], "Bearer ") {
			credential.text = strings.TrimPrefix(vals[0], "Bearer ")
		}
	} else if vals, ok := r.Header["X-Proxy-Key"]; ok {
		credential = value{present: true}
		if len(vals) > 0 {
			credential.text = vals[0]
		}
	}
	return credential.present && subtle.ConstantTimeCompare([]byte(credential.text), []byte(p.cfg.Key)) == 1
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, method string) {
	c, err := parseControls(r.Body, r.Header.Get("Content-Type"), r.URL.Query())
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, err.Error())
		return
	}
	if !p.authorize(r, c) {
		writeJSON(w, http.StatusUnauthorized, "invalid key")
		return
	}
	target, err := buildTargetURL(c, p.cfg.DefaultScheme)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err = p.validateTarget(r.Context(), target); err != nil {
		writeJSON(w, statusForTargetError(err), err.Error())
		return
	}
	// 透传路径的请求体上限: Content-Length 已知时直接拒绝, 未知(chunked)时
	// 边读边计数, 超限中断并返回 413。控制类 body 已在 parseControls 内被
	// maxControlBody 截断, 这里统一再包一层, 实际取两者较小值。
	if r.ContentLength > p.cfg.MaxRequestBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, "请求体超过上限")
		return
	}
	var body io.Reader
	if c.body != nil {
		body = &cappedReader{r: c.body, remaining: p.cfg.MaxRequestBody}
	}
	if c.body != nil {
		defer c.body.Close()
	}
	clientRequest, err := http.NewRequestWithContext(r.Context(), method, target.String(), body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, "构造请求失败: "+err.Error())
		return
	}
	copyRequestHeaders(clientRequest.Header, r.Header)
	// 来源 IP 防伪造: 删除客户端可控的转发头, 改写为真实对端地址, 避免
	// 上游基于 X-Forwarded-For/Forwarded/X-Real-IP 的鉴权被伪造来源绕过。
	clientRequest.Header.Del("X-Forwarded-For")
	clientRequest.Header.Del("Forwarded")
	clientRequest.Header.Del("X-Real-IP")
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		clientRequest.Header.Set("X-Forwarded-For", host)
	}
	if c.replacedBody {
		clientRequest.Header.Del("Content-Encoding")
	}
	if c.contentType != "" {
		clientRequest.Header.Set("Content-Type", c.contentType)
	}
	if clientRequest.Header.Get("User-Agent") == "" {
		clientRequest.Header.Set("User-Agent", "github.com/FasterEdge/ProxyArea/"+version)
	}
	start := time.Now()
	resp, err := p.client.Do(clientRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		status := http.StatusBadGateway
		if errors.Is(err, errBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		} else if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
			status = http.StatusGatewayTimeout
		}
		writeJSON(w, status, "上游请求失败: "+err.Error())
		return
	}
	defer resp.Body.Close()
	// 目标 URL 可含换行(如 %0A 解码), 记录前消毒防日志注入
	red := strings.ReplaceAll(target.Redacted(), "\n", "")
	log.Printf("[%s] %s -> %d (%s) from %s", method, red, resp.StatusCode, time.Since(start).Round(time.Millisecond), r.RemoteAddr)
	// 响应体上限(已知长度): 在写响应头之前就拒绝, 客户端拿到明确的 502,
	// 而不是被截断的半截 body。未知长度(chunked)由 writeResponseBody 兜。
	if p.cfg.MaxResponseBody > 0 && resp.ContentLength > p.cfg.MaxResponseBody {
		writeJSON(w, http.StatusBadGateway, "上游响应体超过上限")
		return
	}
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if err := p.writeResponseBody(w, resp.Body); err != nil {
		// 响应头已发出, 无法再改状态码; 中断连接, 让客户端看到传输失败,
		// 而不是把截断后的 body 当成完整响应。
		log.Printf("响应体转发中断(上限 %d): %v", p.cfg.MaxResponseBody, err)
		abortStream()
	}
}

func (p *Proxy) validateTarget(ctx context.Context, u *url.URL) ([]net.IP, error) {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("目标 URL 非法")
	}
	if err := p.checkAllowHost(u); err != nil {
		return nil, err
	}
	// 以上都是字面量匹配, 只能挡住"写死的内网地址"; 真正的边界是下面的
	// 解析后 IP 校验, DNS rebinding 与 CNAME 指向内网都靠它兜住。
	return p.resolveChecked(ctx, u.Hostname())
}

// checkAllowHost 只做主机名/端口的字面量白名单匹配; 空列表表示不限制主机名。
func (p *Proxy) checkAllowHost(u *url.URL) error {
	if len(p.cfg.AllowHosts) == 0 {
		return nil
	}
	// hostPort 保留端口信息; 无端口时仅主机名。
	hostPort := u.Host
	if u.Port() == "" {
		hostPort = u.Hostname()
	}
	for _, h := range p.cfg.AllowHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		// 白名单条目支持两种形式: "host"(仅主机名, 不限制端口) 与
		// "host:port"(精确匹配主机+端口, 防止 /connect 对白名单主机做任意端口扫描)。
		if strings.Contains(h, ":") {
			if strings.EqualFold(h, hostPort) {
				return nil
			}
		} else if strings.EqualFold(h, u.Hostname()) {
			return nil
		}
	}
	return errors.New("目标主机不在白名单内: " + u.Host)
}

var hopByHop = map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true, "Content-Length": true}

func copyRequestHeaders(dst, src http.Header) {
	copyEndToEndHeaders(dst, src, true)
}

func copyResponseHeaders(dst, src http.Header) {
	copyEndToEndHeaders(dst, src, false)
}

func copyEndToEndHeaders(dst, src http.Header, request bool) {
	blocked := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			blocked[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if hopByHop[ck] || blocked[ck] || (request && (ck == "Authorization" || ck == "X-Proxy-Key")) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
func writeJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
