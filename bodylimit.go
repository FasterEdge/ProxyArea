// ─────────────────────────────────────────────────────────────
// FasterEdge 开源项目
// Github: https://github.com/FasterEdge
// Gitee:  https://gitee.com/FasterEdge
// ─────────────────────────────────────────────────────────────
package main

import (
	"errors"
	"io"
	"net/http"
)

// cappedReader 对流式 body 施加硬上限: 读满上限后若仍有数据, 立即返回
// errBodyTooLarge, 而不是静默截断后当成"成功转发"。
// 恰好等于上限时不额外读(靠上游自然 EOF), 只有越界时才多一次探测 Read。
type cappedReader struct {
	r         io.Reader
	remaining int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		if n > 0 {
			return 0, errBodyTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// statusForTargetError 把统一校验返回的错误映射为 HTTP 状态码,
// 三条路径(forward / 重定向 / CONNECT)共用, 避免各自写一套映射。
func statusForTargetError(err error) int {
	switch {
	case errors.Is(err, errTargetDenied):
		return http.StatusForbidden
	case errors.Is(err, errResolveFailed):
		return http.StatusBadGateway
	}
	return http.StatusForbidden
}

// writeResponseBody 按 MaxResponseBody 转发上游响应体。
// 长度未知(chunked)时边转发边计数, 超限即返回错误, 由调用方中断连接,
// 而不是把截断后的半截响应伪装成完整响应。
func (p *Proxy) writeResponseBody(w http.ResponseWriter, body io.Reader) error {
	if p.cfg.MaxResponseBody <= 0 {
		_, err := io.Copy(w, body)
		return err
	}
	_, err := io.Copy(w, &cappedReader{r: body, remaining: p.cfg.MaxResponseBody})
	return err
}

// abortStream 终止一个已经开始写响应的连接: 此时响应头已发出, 无法再改状态码,
// 唯一诚实的做法是中断传输(panic(http.ErrAbortHandler) 由 net/http 静默回收连接),
// 而不是让客户端把被截断的 body 当成完整响应。
func abortStream() {
	panic(http.ErrAbortHandler)
}
