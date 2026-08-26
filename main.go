package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProxyArea - 轻量通用 HTTP 代理转发器
// By tyza66 (FasterEdge)
// 支持 GET/POST/PUT/PATCH/DELETE 转发、密钥认证、HTTPS 监听、目标主机白名单
// 纯标准库实现, 免 CGO, 跨平台。

const (
	version = "1.0.20260826"
	rootMsg = "ProxyArea 1.0.20260826 By tyza66"
)

var (
	proxyKey           string
	httpsEnabled       bool
	certFile           string
	keyFile            string
	listenAddr         string
	timeout            time.Duration
	defaultScheme      string
	allowHosts         []string
	insecureSkipVerify bool
)

// httpClient 带超时的统一客户端
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
		DisableCompression: false,
	},
}

// hopByHop 跳变头, 不向前转发
var hopByHop = map[string]bool{
	"Connection":         true,
	"Keep-Alive":         true,
	"Proxy-Authenticate": true,
	"Proxy-Authorization": true,
	"Te":                 true,
	"Trailer":            true,
	"Transfer-Encoding":  true,
	"Upgrade":            true,
	"Host":               true,
	"Content-Length":     true,
}

func main() {
	flag.StringVar(&proxyKey, "key", "", "访问代理的密钥(可选，留空则不验证)")
	flag.BoolVar(&httpsEnabled, "https", false, "本服务是否启用 HTTPS(可选，默认 false)")
	flag.StringVar(&certFile, "cert_file", "", "HTTPS 证书文件路径")
	flag.StringVar(&keyFile, "key_file", "", "HTTPS 证书私钥文件路径")
	flag.StringVar(&listenAddr, "addr", ":8080", "监听地址(可选，默认 :8080)")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "上游请求超时(可选，默认 30s)")
	flag.StringVar(&defaultScheme, "target-scheme", "http", "目标 URL 未带协议时的默认协议(可选，默认 http)")
	hostsRaw := flag.String("allow-hosts", "", "目标主机白名单, 逗号分隔; 留空表示不限制")
	flag.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "访问自签名 HTTPS 目标时跳过证书校验(可选，默认 false)")
	flag.Parse()

	if *hostsRaw != "" {
		for _, h := range strings.Split(*hostsRaw, ",") {
			if h = strings.TrimSpace(h); h != "" {
				allowHosts = append(allowHosts, h)
			}
		}
	}
	httpClient.Timeout = timeout
	httpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureSkipVerify}

	if httpsEnabled && (certFile == "" || keyFile == "") {
		log.Fatal("启用 HTTPS 需要同时提供 --cert_file 和 --key_file")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, rootMsg)
	})
	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, http.MethodGet)
	})
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, http.MethodPost)
	})
	// 通用代理: 转发请求自身的方法 (GET /proxy, POST /proxy, PUT /proxy/post 均可)
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, "解析表单失败: "+err.Error())
			return
		}
		forward(w, r, r.Method)
	})
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, "解析表单失败: "+err.Error())
			return
		}
		forward(w, r, r.Method)
	})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("ProxyArea v%s 启动, 监听 %s", version, listenAddr)
	if httpsEnabled {
		log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
	}
	log.Fatal(srv.ListenAndServe())
}

// checkKey 校验访问密钥; 未配置密钥则直接放行
func checkKey(w http.ResponseWriter, r *http.Request) bool {
	if proxyKey == "" {
		return true
	}
	key := r.PostFormValue("key")
	if key == "" {
		key = r.URL.Query().Get("key")
	}
	if key == proxyKey {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, "invalid key")
	return false
}

// extractValue 优先取表单字段, 其次取 query 参数
func extractValue(r *http.Request, name string) string {
	if v := r.PostFormValue(name); v != "" {
		return v
	}
	return r.URL.Query().Get(name)
}

// buildTargetURL 解析并校验目标 URL, 附带 304 编码的 params 拼接
func buildTargetURL(r *http.Request) (string, int, string) {
	target := extractValue(r, "url")
	if target == "" {
		return "", http.StatusBadRequest, "缺少 url 参数"
	}
	if d, err := url.QueryUnescape(target); err == nil {
		target = d
	}

	// 协议: URL 自带则保留; 否则用 https 参数(优先)或 target-scheme
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		scheme := defaultScheme
		if extractValue(r, "https") == "true" {
			scheme = "https"
		}
		target = scheme + "://" + target
	}

	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", http.StatusBadRequest, "目标 URL 非法: " + target
	}
	if !hostAllowed(u.Host) {
		return "", http.StatusForbidden, "目标主机不在白名单内: " + u.Host
	}

	// params 追加到 query
	params := extractValue(r, "params")
	if params != "" {
		if d, err := url.QueryUnescape(params); err == nil {
			params = d
		}
		if u.RawQuery != "" {
			u.RawQuery += "&" + params
		} else {
			u.RawQuery = params
		}
	}
	return u.String(), 0, ""
}

// hostAllowed 白名单校验(逐端口拆分后比较主机名)
func hostAllowed(host string) bool {
	if len(allowHosts) == 0 {
		return true
	}
	h := host
	if hv, _, err := net.SplitHostPort(host); err == nil {
		h = hv
	}
	for _, a := range allowHosts {
		if strings.EqualFold(h, a) {
			return true
		}
	}
	return false
}

// forward 统一转发逻辑
func forward(w http.ResponseWriter, r *http.Request, method string) {
	if !checkKey(w, r) {
		return
	}
	target, status, msg := buildTargetURL(r)
	if target == "" {
		writeJSON(w, status, msg)
		return
	}

	var body io.Reader
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, "读取请求体失败: "+err.Error())
			return
		}
		// 恢复 body, 让 PostFormValue 仍能解析 url/key/params
		r.Body = io.NopCloser(bytes.NewReader(raw))
		_ = r.ParseForm()
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, target, body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, "构造请求失败: "+err.Error())
		return
	}
	copyHeaders(req.Header, r.Header)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if ua := req.Header.Get("User-Agent"); ua == "" {
		req.Header.Set("User-Agent", "ProxyArea/"+version)
	}

	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, "上游请求失败: "+err.Error())
		return
	}
	defer resp.Body.Close()

	log.Printf("[%s] %s -> %d (%s) from %s",
		r.Method, target, resp.StatusCode, time.Since(start).Round(time.Millisecond), r.RemoteAddr)

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// copyHeaders 复制请求/响应头(剔除跳变头)
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// writeJSON 输出统一的 JSON 错误
func writeJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	msg = strings.ReplaceAll(msg, `"`, `\"`)
	io.WriteString(w, `{"error":"`+msg+`"}`)
}