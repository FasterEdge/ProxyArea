package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, rootMsg)
	})
	mux.HandleFunc("/get", p.route(http.MethodGet))
	mux.HandleFunc("/post", p.route(http.MethodPost))
	mux.HandleFunc("/proxy", p.route(""))
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
	if p.cfg.Key != "" && (!credential.present || subtle.ConstantTimeCompare([]byte(credential.text), []byte(p.cfg.Key)) != 1) {
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
	if c.replacedBody {
		clientRequest.Header.Del("Content-Encoding")
	}
	if c.contentType != "" {
		clientRequest.Header.Set("Content-Type", c.contentType)
	}
	if clientRequest.Header.Get("User-Agent") == "" {
		clientRequest.Header.Set("User-Agent", "ProxyArea/"+version)
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
	log.Printf("[%s] %s -> %d (%s) from %s", method, target.Redacted(), resp.StatusCode, time.Since(start).Round(time.Millisecond), r.RemoteAddr)
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
	for _, h := range p.cfg.AllowHosts {
		if strings.EqualFold(strings.TrimSpace(h), u.Hostname()) {
			return nil
		}
	}
	return errors.New("目标主机不在白名单内: " + u.Hostname())
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
