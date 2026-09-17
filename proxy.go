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
}

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
	if cfg.Transport == nil {
		cfg.Transport = http.DefaultTransport
	}
	p := &Proxy{cfg: cfg}
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
		if err := p.validateTarget(req.URL); err != nil {
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
		if err = p.validateTarget(target); err != nil {
			writeJSON(w, http.StatusForbidden, err.Error())
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

		// 建立到目标的 TCP 连接
		dialer := &net.Dialer{Timeout: p.cfg.Timeout}
		upstream, err := dialer.DialContext(r.Context(), "tcp", target.Host)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, err.Error())
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
	if err = p.validateTarget(target); err != nil {
		writeJSON(w, http.StatusForbidden, err.Error())
		return
	}
	var body io.Reader
	if c.body != nil {
		body = c.body
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
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
			status = http.StatusGatewayTimeout
		}
		writeJSON(w, status, "上游请求失败: "+err.Error())
		return
	}
	defer resp.Body.Close()
	// 目标 URL 可含换行(如 %0A 解码), 记录前消毒防日志注入
	red := strings.ReplaceAll(target.Redacted(), "\n", "")
	log.Printf("[%s] %s -> %d (%s) from %s", method, red, resp.StatusCode, time.Since(start).Round(time.Millisecond), r.RemoteAddr)
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) validateTarget(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return errors.New("目标 URL 非法")
	}
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
