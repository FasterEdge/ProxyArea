// ─────────────────────────────────────────────────────────────
// FasterEdge 开源项目
// Github: https://github.com/FasterEdge
// Gitee:  https://gitee.com/FasterEdge
// ─────────────────────────────────────────────────────────────
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// 目标校验的失败需要区分 HTTP 状态: 被策略拒绝 → 403, 解析失败 → 502。
var (
	errTargetDenied  = errors.New("目标被安全策略拒绝")
	errResolveFailed = errors.New("目标主机解析失败")
)

type ipClass int

const (
	ipPublic ipClass = iota
	ipLoopback
	ipPrivate
	ipLinkLocal
	ipUnspecified
	ipMulticast
)

func (c ipClass) String() string {
	switch c {
	case ipLoopback:
		return "回环"
	case ipPrivate:
		return "私网"
	case ipLinkLocal:
		return "链路本地"
	case ipUnspecified:
		return "未指定地址"
	case ipMulticast:
		return "组播"
	}
	return "公网"
}

// cgnatPrefix 是 100.64.0.0/10(运营商级 NAT), net.IP.IsPrivate 不覆盖该段。
var cgnatPrefix = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// classifyIP 给出单个已解析地址的风险类别。
// IPv4-mapped IPv6(::ffff:a.b.c.d) 必须先归一化为 IPv4, 否则 "::ffff:127.0.0.1"
// 这类写法会绕过按 IPv4 前缀写的私网/链路本地判定。
func classifyIP(ip net.IP) ipClass {
	if ip == nil {
		return ipUnspecified
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	switch {
	case ip.IsUnspecified():
		return ipUnspecified
	case ip.IsMulticast():
		return ipMulticast
	case ip.IsLoopback():
		return ipLoopback
	case ip.IsLinkLocalUnicast():
		return ipLinkLocal
	case ip.IsPrivate():
		return ipPrivate
	case cgnatPrefix.Contains(ip):
		return ipPrivate
	}
	return ipPublic
}

// resolveTarget 解析主机名。主机名是 IP 字面量时直接返回, 不做 DNS 查询;
// 测试可通过 Config.LookupIP 注入解析结果。
func (p *Proxy) resolveTarget(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	// 无论用默认解析器还是注入的解析器, 都绑定请求超时:
	// 慢 DNS 不该把整体超时拖到不可控。
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	if p.cfg.LookupIP != nil {
		return p.cfg.LookupIP(ctx, host)
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// checkResolvedIPs 是唯一的『解析后 IP 校验』实现: forward、重定向、CONNECT 与
// 拨号阶段全部复用, 避免各写一套导致策略漂移。
// 任一解析结果落在被拒网段即整体拒绝(不挑选"看起来安全"的那个 IP)。
func (p *Proxy) checkResolvedIPs(host string, ips []net.IP) error {
	if len(ips) == 0 {
		return fmt.Errorf("目标主机 %s 没有可用地址: %w", host, errResolveFailed)
	}
	for _, ip := range ips {
		class := classifyIP(ip)
		if class == ipPublic {
			continue
		}
		if p.cfg.AllowPrivateNets && (class == ipLoopback || class == ipPrivate || class == ipLinkLocal) {
			continue
		}
		return fmt.Errorf("目标主机 %s 解析到 %s(%s), 拒绝访问: %w", host, ip, class, errTargetDenied)
	}
	return nil
}

// resolveChecked 解析并校验, 返回已通过校验的地址列表。
func (p *Proxy) resolveChecked(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := p.resolveTarget(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("目标主机 %s 解析失败: %v: %w", host, err, errResolveFailed)
	}
	if err := p.checkResolvedIPs(host, ips); err != nil {
		return nil, err
	}
	return ips, nil
}

// dialGuarded 在拨号前重新解析并校验, 然后直接连接校验过的 IP。
// 解析、校验、连接使用同一份结果, 消除 DNS rebinding 的 TOCTOU 窗口:
// 即使上游 DNS 在校验之后被改成内网地址, 实际连接的目标仍是校验过的那一个。
func (p *Proxy) dialGuarded(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := p.resolveChecked(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: p.cfg.Timeout, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("连接目标 %s 失败: %v", addr, lastErr)
}
