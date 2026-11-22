package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── 解析后 IP 校验: 分类器 ──────────────────────────────────

func TestClassifyIPBlocksReservedRanges(t *testing.T) {
	cases := []struct {
		ip   string
		want ipClass
	}{
		{"10.0.0.8", ipPrivate},
		{"172.16.5.4", ipPrivate},
		{"172.31.255.255", ipPrivate},
		{"192.168.1.1", ipPrivate},
		{"169.254.169.254", ipLinkLocal},
		{"100.64.0.1", ipPrivate}, // 运营商级 NAT 100.64/10
		{"100.127.255.255", ipPrivate},
		{"127.0.0.1", ipLoopback},
		{"::1", ipLoopback},
		{"8.8.8.8", ipPublic},
		{"1.1.1.1", ipPublic},
		{"2607:f8b0:4004:809::200e", ipPublic},
		{"172.32.0.1", ipPublic},
		{"100.63.255.255", ipPublic},
		{"100.128.0.0", ipPublic},
		{"0.0.0.0", ipUnspecified},
		{"::", ipUnspecified},
		{"224.0.0.1", ipMulticast},
		// 保留段 240.0.0.0/4(含受限广播 255.255.255.255)
		{"240.0.0.1", ipReserved},
		{"255.255.255.255", ipReserved},
		{"255.255.255.254", ipReserved},
		{"239.255.255.255", ipMulticast},
		// 基准测试 198.18.0.0/15
		{"198.18.0.1", ipReserved},
		{"198.19.255.255", ipReserved},
		{"198.17.255.255", ipPublic},
		{"198.20.0.1", ipPublic},
		// 文档段 TEST-NET-1/2/3
		{"192.0.2.1", ipReserved},
		{"198.51.100.1", ipReserved},
		{"203.0.113.10", ipReserved},
		{"192.0.1.1", ipPublic},
		{"192.0.2.0", ipReserved},
		{"192.0.0.1", ipPublic},
		{"203.0.113.255", ipReserved},
		{"192.0.2.1", ipReserved},
		{"198.51.100.1", ipReserved},
		{"203.0.113.10", ipReserved},
		// 其它标准库不判定的非公网段
		{"100::1", ipReserved}, // 丢弃段 100::/64
		{"2001:db8::1", ipReserved},
		{"2001:db9::1", ipPublic}, // 紧邻文档段之外, 确认没有一刀切
		{"3fff::1", ipReserved},
		{"2001:2::1", ipReserved},
		{"64:ff9b::7f00:1", ipReserved}, // NAT64 内嵌 127.0.0.1
		{"64:ff9b:1::7f00:1", ipReserved},
		{"2002:7f00:1::", ipReserved},   // 6to4 内嵌 127.0.0.1
		{"2001:0:7f00:1::", ipReserved}, // Teredo 内嵌 127.0.0.1
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("ParseIP(%q) = nil", tc.ip)
		}
		if got := classifyIP(ip); got != tc.want {
			t.Errorf("classifyIP(%s) = %s, want %s", tc.ip, got, tc.want)
		}
	}
}

// IPv4-mapped IPv6 是绕过私网校验的经典写法: ::ffff:10.0.0.1 按 IPv6 前缀判定
// 会漏掉。归一化后必须按 IPv4 处理。
func TestClassifyIPNormalizesIPv4Mapped(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want ipClass
	}{
		{"::ffff:127.0.0.1", ipLoopback},
		{"::ffff:10.0.0.1", ipPrivate},
		{"::ffff:169.254.169.254", ipLinkLocal},
		{"::ffff:100.64.0.1", ipPrivate},
		{"::ffff:8.8.8.8", ipPublic},
		{"::ffff:240.0.0.1", ipReserved},
		{"::ffff:198.18.0.1", ipReserved},
		{"::ffff:192.0.2.1", ipReserved},
		{"::ffff:198.51.100.1", ipReserved},
		{"::ffff:203.0.113.10", ipReserved},
		{"::ffff:255.255.255.255", ipReserved},
	} {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("ParseIP(%q) = nil", tc.ip)
		}
		if got := classifyIP(ip); got != tc.want {
			t.Errorf("classifyIP(%s) = %s, want %s", tc.ip, got, tc.want)
		}
	}
}

// stubResolver 注入解析结果, 模拟"主机名白名单放行、解析结果指向内网"的绕过。
func stubResolver(t *testing.T, ips ...string) func(*Config) {
	t.Helper()
	parsed := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad ip %q", s)
		}
		parsed = append(parsed, ip)
	}
	return func(c *Config) {
		c.LookupIP = func(context.Context, string) ([]net.IP, error) { return parsed, nil }
	}
}

// 同一批用例覆盖 forward 与 CONNECT 两条请求路径, 证明它们复用同一校验函数。
func TestPrivateTargetRejectedOnAllPaths(t *testing.T) {
	cases := []struct {
		name   string
		target string
		cfg    func(*Config)
	}{
		{"loopback-v4", "http://127.0.0.1:8080", nil},
		{"private-10", "http://10.0.0.1:8080", nil},
		{"private-172", "http://172.16.0.1:8080", nil},
		{"private-192", "http://192.168.0.1:8080", nil},
		{"linklocal-metadata", "http://169.254.169.254:8080", nil},
		{"cgnat-100-64", "http://100.64.0.1:8080", nil},
		{"loopback-v6", "http://[::1]:8080", nil},
		{"ipv4-mapped-v6", "http://[::ffff:10.0.0.1]:8080", nil},
		{"unspecified", "http://0.0.0.0:8080", nil},
		{"multicast", "http://224.0.0.1:8080", nil},
		// 保留段/基准测试段/受限广播: 标准库不判定, 过去会当公网放行
		{"reserved-240", "http://240.0.0.1:8080", nil},
		{"reserved-benchmark", "http://198.18.0.1:8080", nil},
		{"reserved-testnet1", "http://192.0.2.1:8080", nil},
		{"reserved-testnet2", "http://198.51.100.1:8080", nil},
		{"reserved-testnet3", "http://203.0.113.1:8080", nil},
		{"reserved-broadcast", "http://255.255.255.255:8080", nil},
		{"reserved-ipv6-doc", "http://[2001:db8::1]:8080", nil},
		{"reserved-ipv6-discard", "http://[100::1]:8080", nil},
		// IPv4-mapped IPv6 写法绕过保留段判定
		{"reserved-mapped-240", "http://[::ffff:240.0.0.1]:8080", nil},
		{"reserved-mapped-testnet1", "http://[::ffff:192.0.2.1]:8080", nil},
		// NAT64/6to4/Teredo 内嵌回环 IPv4
		{"reserved-nat64-loopback", "http://[64:ff9b::7f00:1]:8080", nil},
		{"reserved-6to4-loopback", "http://[2002:7f00:1::]:8080", nil},
		{"reserved-teredo-loopback", "http://[2001:0:7f00:1::]:8080", nil},
		// 主机名白名单放行, 但解析结果指向内网(DNS rebinding 的经典形态)
		{"rebind-host-to-loopback", "http://evil.example.com:8080", stubResolver(t, "127.0.0.1")},
		{"rebind-host-to-metadata", "http://evil.example.com:8080", stubResolver(t, "169.254.169.254")},
		{"rebind-host-to-private", "http://evil.example.com:8080", stubResolver(t, "10.1.2.3")},
		{"rebind-host-to-mapped-v6", "http://evil.example.com:8080", stubResolver(t, "::ffff:192.168.0.1")},
		// 白名单主机名解析到保留段
		{"rebind-host-to-reserved-240", "http://evil.example.com:8080", stubResolver(t, "240.0.0.1")},
		{"rebind-host-to-testnet1", "http://evil.example.com:8080", stubResolver(t, "192.0.2.1")},
		{"rebind-host-to-benchmark", "http://evil.example.com:8080", stubResolver(t, "198.18.0.1")},
		{"rebind-host-to-mapped-reserved", "http://evil.example.com:8080", stubResolver(t, "::ffff:240.0.0.1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{AllowHosts: []string{"evil.example.com"}}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			p, err := NewProxy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			s := httptest.NewServer(p.Handler())
			defer s.Close()

			// 路径 1: forward
			resp := do(t, "GET", s.URL+"/proxy?url="+url.QueryEscape(tc.target), nil, nil)
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("forward: status=%d body=%s", resp.StatusCode, b)
			}

			// 路径 2: CONNECT 隧道(旧实现在此处只做主机名匹配)
			resp = do(t, "GET", s.URL+"/connect?url="+url.QueryEscape(tc.target), nil, nil)
			b, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("connect: status=%d body=%s", resp.StatusCode, b)
			}
		})
	}
}

// 白名单条目是"看起来正常"的主机名, 解析结果却指向云元数据地址: 必须 403。
func TestAllowlistedHostnameResolvingToMetadataIsRejected(t *testing.T) {
	p, err := NewProxy(Config{
		AllowHosts: []string{"metadata.attacker.test"},
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "GET", s.URL+"/proxy?url=http://metadata.attacker.test/latest/meta-data", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// 多解析结果里有一个内网地址: 整体拒绝, 不挑"看起来安全"的那个。
func TestOnePrivateIPAmongManyRejectsWholeTarget(t *testing.T) {
	p, err := NewProxy(Config{
		AllowHosts: []string{"mixed.example.test"},
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.validateTarget(context.Background(), &url.URL{Scheme: "http", Host: "mixed.example.test"})
	if !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v, want errTargetDenied", err)
	}
}

// 解析失败 → 502(与"被策略拒绝"的 403 区分开)。
func TestUnresolvableHostMapsToBadGateway(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lookup func(context.Context, string) ([]net.IP, error)
	}{
		{"error", func(context.Context, string) ([]net.IP, error) { return nil, errors.New("no such host") }},
		{"empty", func(context.Context, string) ([]net.IP, error) { return nil, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProxy(Config{LookupIP: tc.lookup})
			if err != nil {
				t.Fatal(err)
			}
			s := httptest.NewServer(p.Handler())
			defer s.Close()
			resp := do(t, "GET", s.URL+"/proxy?url=http://nope.invalid/x", nil, nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status=%d", resp.StatusCode)
			}
		})
	}
}

// 重定向路径: 每一跳都要重新做"解析后 IP 校验"。
// 直接调用 client.CheckRedirect 精确断言, 避免被 hop-1 的本地回环策略干扰。
func TestRedirectHopRechecksResolvedIP(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		cfg     func(*Config)
		wantErr bool
	}{
		{"metadata-ip", "http://169.254.169.254/latest/meta-data", func(c *Config) { c.AllowPrivateNets = false }, true},
		{"private-10", "http://10.0.0.5/x", func(c *Config) { c.AllowPrivateNets = false }, true},
		{"loopback", "http://127.0.0.1:1/x", func(c *Config) { c.AllowPrivateNets = false }, true},
		{"unspecified", "http://0.0.0.0:1/x", nil, true},
		{"multicast", "http://224.0.0.1:1/x", nil, true},
		// 白名单主机名解析到内网: 逐跳重新校验必须拒绝
		{"allowlisted-but-private", "http://rebound.example.test/x", stubResolver(t, "127.0.0.1"), true},
		{"allowlisted-but-metadata", "http://rebound.example.test/x", stubResolver(t, "169.254.169.254"), true},
		// 公网地址应放行, 确认校验没有一刀切。
		// 注意不能用 203.0.113.10: 那是 TEST-NET-3 文档段, 已被归为保留段拒绝。
		{"public-ok", "http://1.1.1.1/x", nil, false},
		// 保留段/基准测试段/文档段/受限广播在重定向逐跳校验里同样必须被拒
		{"reserved-240", "http://240.0.0.1/x", nil, true},
		{"reserved-benchmark", "http://198.18.0.1/x", nil, true},
		{"reserved-testnet1", "http://192.0.2.1/x", nil, true},
		{"reserved-testnet2", "http://198.51.100.1/x", nil, true},
		{"reserved-testnet3", "http://203.0.113.10/x", nil, true},
		{"reserved-broadcast", "http://255.255.255.255/x", nil, true},
		{"reserved-ipv6-doc", "http://[2001:db8::1]/x", nil, true},
		{"reserved-mapped-240", "http://[::ffff:240.0.0.1]/x", nil, true},
		{"allowlisted-but-reserved", "http://rebound.example.test/x", stubResolver(t, "240.0.0.1"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			p, err := NewProxy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			target, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			req := &http.Request{URL: target, Header: http.Header{}}
			err = p.client.CheckRedirect(req, nil)
			if tc.wantErr && err == nil {
				t.Fatalf("redirect to %s accepted", tc.target)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("redirect to %s rejected: %v", tc.target, err)
			}
			// 重定向时必须剥掉凭据头, 否则跨主机重定向会泄露 key
			if !tc.wantErr {
				req.Header.Set("Authorization", "Bearer leaked")
				req.Header.Set("X-Proxy-Key", "leaked")
				if err := p.client.CheckRedirect(req, nil); err != nil {
					t.Fatal(err)
				}
				if req.Header.Get("Authorization") != "" || req.Header.Get("X-Proxy-Key") != "" {
					t.Fatal("credentials survived redirect")
				}
			}
		})
	}
}

// 端到端: 上游 302 跳到被禁地址, 客户端拿到 502(与既有"重定向失败"映射一致)。
func TestRedirectToBlockedTargetEndToEnd(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://0.0.0.0:1/x", http.StatusFound)
	}))
	defer up.Close()
	p, err := NewProxy(localConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "GET", s.URL+"/proxy?url="+url.QueryEscape(up.URL), nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// ── DNS rebinding: TOCTOU 窗口关闭 ─────────────────────────

// 校验与拨号各自解析一次时, 攻击者可在两次之间把 DNS 改到内网。
// 这里让解析器第一次返回公网 IP、之后返回内网 IP, 验证拨号阶段重新校验会拒绝。
func TestDNSRebindingBetweenCheckAndDialIsRejected(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	p, err := NewProxy(Config{
		AllowHosts: []string{"flip.example.test"},
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if calls == 1 {
				return []net.IP{net.ParseIP("8.8.8.8")}, nil
			}
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 第一次校验通过(公网)
	if _, err := p.resolveChecked(context.Background(), "flip.example.test"); err != nil {
		t.Fatalf("first check: %v", err)
	}
	// 随后 DNS 变内网, 拨号前的重新校验必须拒绝
	if _, err := p.dialGuarded(context.Background(), "tcp", "flip.example.test:80"); !errors.Is(err, errTargetDenied) {
		t.Fatalf("err=%v, want errTargetDenied", err)
	}
}

// 拨号必须连到"本次校验过的那个 IP", 而不是再次交给系统解析主机名。
// 用一个真实监听 + 注入解析结果来证明: 只有用注入 IP 才可能连上。
func TestDialGuardedDialsTheValidatedIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, err := NewProxy(Config{
		AllowPrivateNets: true,
		AllowHosts:       []string{"fake-upstream.test"},
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := p.dialGuarded(context.Background(), "tcp", net.JoinHostPort("fake-upstream.test", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

// dialGuarded 自身必须拒绝内网地址(即使调用方漏掉了 validateTarget)。
func TestDialGuardedRejectsReservedAddresses(t *testing.T) {
	p, err := NewProxy(Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{
		"127.0.0.1:80", "10.0.0.1:80", "169.254.169.254:80", "[::ffff:192.168.0.1]:80",
		"0.0.0.0:80", "[::1]:80",
		// 保留段/基准测试段/文档段/受限广播: 拨号阶段同样恒拒
		"240.0.0.1:80", "198.18.0.1:80", "192.0.2.1:80", "198.51.100.1:80",
		"203.0.113.10:80", "255.255.255.255:80",
		"[::ffff:240.0.0.1]:80", "[2001:db8::1]:80", "[100::1]:80",
		"[64:ff9b::7f00:1]:80", "[2002:7f00:1::]:80", "[2001:0:7f00:1::]:80",
	} {
		conn, err := p.dialGuarded(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
			t.Fatalf("dialed %s", addr)
		}
		if !errors.Is(err, errTargetDenied) {
			t.Fatalf("dial %s: err=%v, want errTargetDenied", addr, err)
		}
	}
}

// --allow-private-nets 只能放行回环/私网/链路本地; 组播、未指定地址与保留段
// (240.0.0.0/4、198.18.0.0/15、TEST-NET-1/2/3、255.255.255.255)恒被拒绝,
// 否则该开关会把整个转发器变成任意地址打洞器。
func TestAllowPrivateNetsDoesNotOpenReservedRanges(t *testing.T) {
	p, err := NewProxy(Config{AllowPrivateNets: true})
	if err != nil {
		t.Fatal(err)
	}
	denied := []string{
		"240.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.1",
		"198.51.100.1", "203.0.113.10", "224.0.0.1", "0.0.0.0",
		"::ffff:240.0.0.1", "2001:db8::1", "100::1", "64:ff9b::7f00:1",
	}
	for _, s := range denied {
		if err := p.checkResolvedIPs("x", []net.IP{net.ParseIP(s)}); !errors.Is(err, errTargetDenied) {
			t.Errorf("AllowPrivateNets=true 放行了 %s: err=%v", s, err)
		}
	}
	allowed := []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1"}
	for _, s := range allowed {
		if err := p.checkResolvedIPs("x", []net.IP{net.ParseIP(s)}); err != nil {
			t.Errorf("AllowPrivateNets=true 拒绝了 %s: %v", s, err)
		}
	}
}

// 默认 Transport 必须是克隆: 直接改传入的 http.DefaultTransport 会污染进程全局状态。
func TestDefaultTransportIsClonedNotMutated(t *testing.T) {
	tr := http.DefaultTransport.(*http.Transport)
	before := tr.DialContext
	if _, err := NewProxy(Config{}); err != nil {
		t.Fatal(err)
	}
	after := tr.DialContext
	if reflect.ValueOf(before) != reflect.ValueOf(after) {
		t.Fatal("http.DefaultTransport.DialContext was mutated")
	}
}

// 自定义 Transport 的其它设置(如 MaxIdleConns)必须保留。
func TestCustomTransportSettingsPreserved(t *testing.T) {
	tr := &http.Transport{MaxIdleConns: 7}
	p, err := NewProxy(localConfig(func(c *Config) { c.Transport = tr }))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := p.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport type changed")
	}
	if got == tr {
		t.Fatal("expected a clone, got the caller's Transport")
	}
	if got.MaxIdleConns != 7 {
		t.Fatalf("MaxIdleConns=%d, want 7", got.MaxIdleConns)
	}
	if got.DialContext == nil {
		t.Fatal("dial guard not installed")
	}
	if tr.DialContext != nil {
		t.Fatal("caller's Transport was mutated")
	}
}

// ── 请求体 / 响应体上限 ────────────────────────────────────

func TestBodyLimitDefaultsAndOverrides(t *testing.T) {
	p, err := NewProxy(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.MaxRequestBody != DefaultMaxRequestBody || p.cfg.MaxResponseBody != DefaultMaxResponseBody {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	p, err = NewProxy(Config{MaxRequestBody: 32, MaxResponseBody: 64})
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.MaxRequestBody != 32 || p.cfg.MaxResponseBody != 64 {
		t.Fatalf("overrides not applied: %+v", p.cfg)
	}
	p, err = NewProxy(Config{MaxRequestBody: -5, MaxResponseBody: -5})
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.MaxRequestBody != DefaultMaxRequestBody || p.cfg.MaxResponseBody != DefaultMaxResponseBody {
		t.Fatalf("negative not normalized: %+v", p.cfg)
	}
}

func TestCappedReader(t *testing.T) {
	// 超限: 读满上限后仍有数据 → 返回 errBodyTooLarge, 不静默截断
	cr := &cappedReader{r: strings.NewReader("abcdefgh"), remaining: 4}
	out, err := io.ReadAll(cr)
	if string(out) != "abcd" || !errors.Is(err, errBodyTooLarge) {
		t.Fatalf("out=%q err=%v", out, err)
	}
	// 恰好等于上限: 正常 EOF
	cr = &cappedReader{r: strings.NewReader("abcd"), remaining: 4}
	out, err = io.ReadAll(cr)
	if err != nil || string(out) != "abcd" {
		t.Fatalf("exact fit: out=%q err=%v", out, err)
	}
	// 未超限
	cr = &cappedReader{r: strings.NewReader("ab"), remaining: 4}
	if out, err = io.ReadAll(cr); err != nil || string(out) != "ab" {
		t.Fatalf("under limit: out=%q err=%v", out, err)
	}
}

// 透传请求体超限(Content-Length 已知)→ 413。
func TestPassthroughRequestBodyLimitRejectsKnownLength(t *testing.T) {
	up := countingServer(t)
	defer up.Close()
	p, err := NewProxy(localConfig(func(c *Config) { c.MaxRequestBody = 32 }))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "POST", s.URL+"/proxy?url="+url.QueryEscape(up.URL), strings.NewReader(strings.Repeat("y", 33)), map[string]string{"Content-Type": "application/octet-stream"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// 透传请求体超限(chunked, length 未知)→ 流式计数, 同样 413。
func TestPassthroughRequestBodyLimitRejectsChunked(t *testing.T) {
	up := countingServer(t)
	defer up.Close()
	p, err := NewProxy(localConfig(func(c *Config) { c.MaxRequestBody = 64 }))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	req, err := http.NewRequest("POST", s.URL+"/proxy?url="+url.QueryEscape(up.URL), io.NopCloser(&chunkedBody{left: 200}))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1 // 强制 Transfer-Encoding: chunked
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// chunkedBody 每次读返回一块 'z', 模拟慢速分块上传。
type chunkedBody struct{ left int }

func (c *chunkedBody) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.EOF
	}
	c.left--
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'z'
	return 1, nil
}

func countingServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Logf("upstream body read: %v", err)
		}
		_, _ = fmt.Fprint(w, n)
	}))
	t.Cleanup(s.Close)
	return s
}

// 未超限的透传请求体必须完整送达, 不能因新上限被误伤(含 > maxControlBody 的大 body)。
func TestPassthroughRequestBodyBelowLimitPassesThrough(t *testing.T) {
	const extra = 12345
	want := maxControlBody + extra
	up := countingServer(t)
	defer up.Close()
	p, err := NewProxy(localConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "POST", s.URL+"/proxy?url="+url.QueryEscape(up.URL), bytes.NewReader(make([]byte, want)), map[string]string{"Content-Type": "application/octet-stream"})
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(data) != strconv.Itoa(want) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
}

// 响应体超限(Content-Length 已知)→ 502, 不写响应头。
func TestResponseBodyLimitRejectsKnownLength(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("r"), 100))
	}))
	defer up.Close()
	p, err := NewProxy(localConfig(func(c *Config) { c.MaxResponseBody = 32 }))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "GET", s.URL+"/proxy?url="+url.QueryEscape(up.URL), nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// 响应体超限(chunked, length 未知)→ 必须让客户端感知到失败:
// 要么请求阶段就 EOF(net/http 在响应头未刷出前中断连接),
// 要么读到一半报错。绝不允许客户端拿到"没有错误但内容被截断"的响应。
func TestResponseBodyLimitAbortsChunkedStream(t *testing.T) {
	const total = 6400
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 100; i++ {
			_, _ = w.Write(bytes.Repeat([]byte("c"), 64))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer up.Close()
	p, err := NewProxy(localConfig(func(c *Config) { c.MaxResponseBody = 128 }))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp, err := http.Get(s.URL + "/proxy?url=" + url.QueryEscape(up.URL))
	if err != nil {
		// 连接在响应头之前被中断: 客户端明确看到失败, 符合预期
		return
	}
	defer resp.Body.Close()
	var got int64
	buf := make([]byte, 256)
	for {
		n, readErr := resp.Body.Read(buf)
		got += int64(n)
		if readErr != nil {
			// 传输错误: 客户端能看到响应不完整
			return
		}
		if got > 128 {
			t.Fatalf("read %d bytes without error: limit ignored", got)
		}
		if got >= total {
			t.Fatalf("read full %d bytes without error: silent bypass of the limit", got)
		}
	}
}

// 未超限的响应体完整送达。
func TestResponseBodyBelowLimitPassesThrough(t *testing.T) {
	payload := strings.Repeat("p", 4096)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer up.Close()
	p, err := NewProxy(localConfig(func(c *Config) { c.MaxResponseBody = 64 << 10 }))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "GET", s.URL+"/proxy?url="+url.QueryEscape(up.URL), nil, nil)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(data) != payload {
		t.Fatalf("status=%d len=%d", resp.StatusCode, len(data))
	}
}

// ── 解析超时绑定 ───────────────────────────────────────────

// 解析必须继承请求超时, 否则慢 DNS 会把整体超时拖到不可控。
func TestResolveBindsDeadlineToTimeout(t *testing.T) {
	var seen time.Duration
	p, err := NewProxy(Config{
		Timeout: 2 * time.Second,
		LookupIP: func(ctx context.Context, _ string) ([]net.IP, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				t.Fatal("resolve context has no deadline")
			}
			seen = time.Until(dl)
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.resolveTarget(context.Background(), "slow.example.test"); err != nil {
		t.Fatal(err)
	}
	if seen <= 0 || seen > 2*time.Second+200*time.Millisecond {
		t.Fatalf("resolve deadline=%v, want <= 2s", seen)
	}
}

// ── CLI 上限解析 ───────────────────────────────────────────

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"1024", 1024},
		{"16MiB", 16 << 20},
		{"16mib", 16 << 20},
		{"64MB", 64 * 1000 * 1000},
		{"1KiB", 1024},
		{"1B", 1},
		{" 16 MiB ", 16 << 20},
	}
	for _, tc := range cases {
		got, err := parseByteSize(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("parseByteSize(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "abc", "-1", "0", "16MiBx", "16XiB", "1e10"} {
		if _, err := parseByteSize(bad); err == nil {
			t.Errorf("parseByteSize(%q) accepted", bad)
		}
	}
}

func TestByteSizeFlag(t *testing.T) {
	var b byteSizeFlag
	if err := b.Set("8MiB"); err != nil {
		t.Fatal(err)
	}
	if int64(b) != 8<<20 {
		t.Fatalf("b=%d", int64(b))
	}
	if b.String() != strconv.FormatInt(8<<20, 10) {
		t.Fatalf("String()=%q", b.String())
	}
	if err := b.Set("bogus"); err == nil {
		t.Fatal("accepted bogus")
	}
}
