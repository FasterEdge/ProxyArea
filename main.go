// FasterEdge 开源项目 · https://github.com/FasterEdge · https://gitee.com/FasterEdge
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	version = "1.0.20261116"
	rootMsg = "ProxyArea 1.0.20261116 By tyza66"
)

// byteSizeFlag 让上限类参数既接受纯数字(字节), 也接受 "16MiB"、"64MB"、"1024" 这类写法。
type byteSizeFlag int64

func (b *byteSizeFlag) String() string { return strconv.FormatInt(int64(*b), 10) }

func (b *byteSizeFlag) Set(s string) error {
	n, err := parseByteSize(s)
	if err != nil {
		return err
	}
	*b = byteSizeFlag(n)
	return nil
}

func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for _, suffix := range []struct {
		s string
		m int64
	}{{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000}, {"B", 1}} {
		if strings.HasSuffix(s, suffix.s) {
			mult = suffix.m
			s = strings.TrimSpace(strings.TrimSuffix(s, suffix.s))
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效的容量 %q: %w", s, err)
	}
	if n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("无效的容量 %q: 必须为正数", s)
	}
	return n * mult, nil
}

func main() {
	var cfg Config
	var httpsEnabled bool
	var certFile, keyFile, listenAddr, hostsRaw string
	flag.StringVar(&cfg.Key, "key", "", "访问代理的密钥(可选，留空则不验证)")
	flag.BoolVar(&httpsEnabled, "https", false, "本服务是否启用 HTTPS(可选，默认 false)")
	flag.StringVar(&certFile, "cert_file", "", "HTTPS 证书文件路径")
	flag.StringVar(&keyFile, "key_file", "", "HTTPS 证书私钥文件路径")
	flag.StringVar(&listenAddr, "addr", ":8080", "监听地址(可选，默认 :8080)")
	flag.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "上游请求超时(可选，默认 30s)")
	flag.StringVar(&cfg.DefaultScheme, "target-scheme", "http", "目标 URL 未带协议时的默认协议(可选，默认 http)")
	flag.StringVar(&hostsRaw, "allow-hosts", "", "目标主机白名单, 逗号分隔; 留空表示不限制")
	flag.BoolVar(&cfg.RequireAllowlist, "require-allowlist", false, "安全模式: 要求 allow-hosts 至少包含一个目标")
	flag.IntVar(&cfg.MaxRedirects, "max-redirects", 0, "最大重定向次数(0 使用默认 10)")
	flag.BoolVar(&cfg.DisableRedirects, "disable-redirects", false, "不跟随上游重定向")
	flag.BoolVar(&cfg.InsecureSkipVerify, "insecure-skip-verify", false, "访问自签名 HTTPS 目标时跳过证书校验(可选，默认 false)")
	flag.BoolVar(&cfg.AllowPrivateNets, "allow-private-nets", false, "放行回环/私网/链路本地目标(可选，默认 false; 仅限受控内网与本地测试)")
	flag.Var((*byteSizeFlag)(&cfg.MaxRequestBody), "max-request-body", "透传请求体上限(可选，默认 16MiB; 控制类上限固定 8MiB)")
	flag.Var((*byteSizeFlag)(&cfg.MaxResponseBody), "max-response-body", "上游响应体上限(可选，默认 64MiB; 超限返回 502 或中断连接)")
	flag.Parse()
	for _, host := range strings.Split(hostsRaw, ",") {
		if host = strings.TrimSpace(host); host != "" {
			cfg.AllowHosts = append(cfg.AllowHosts, host)
		}
	}
	if httpsEnabled && (certFile == "" || keyFile == "") {
		log.Fatal("启用 HTTPS 需要同时提供 --cert_file 和 --key_file")
	}
	cfg.Transport = &http.Transport{MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}}
	proxy, err := NewProxy(cfg)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: listenAddr, Handler: proxy.Handler(), ReadTimeout: 30 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second}
	log.Printf("ProxyArea v%s 启动, 监听 %s", version, listenAddr)
	if httpsEnabled {
		log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
	}
	log.Fatal(srv.ListenAndServe())
}
