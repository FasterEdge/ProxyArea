// ─────────────────────────────────────────────────────────────
// FasterEdge 开源项目
// Github: https://github.com/FasterEdge
// Gitee:  https://gitee.com/FasterEdge
// ─────────────────────────────────────────────────────────────
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

var addr = flag.String("addr", ":8081", "测试服务器监听地址")

const version = "1.0.20260902"

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
	})
	mux.HandleFunc("/delay", func(w http.ResponseWriter, r *http.Request) {
		d, _ := time.ParseDuration(r.URL.Query().Get("duration"))
		time.Sleep(d)
		handle(w, r)
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("Connection", "X-Drop")
		w.Header().Set("X-Drop", "removed")
		handle(w, r)
	})
	mux.HandleFunc("/", handle)
	fmt.Printf("ProxyArea TestServer v%s 启动, 监听 %s\n", version, *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Println("服务退出:", err)
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	fmt.Printf("[%s] %s %s body=%d\n", time.Now().Format("15:04:05"), r.Method, r.URL.RequestURI(), len(body))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"method": r.Method, "path": r.URL.Path, "raw_query": r.URL.RawQuery,
		"query": r.URL.Query(), "headers": r.Header, "remote_addr": r.RemoteAddr,
		"body_size": len(body), "body": string(body), "body_base64": base64.StdEncoding.EncodeToString(body),
	})
}
