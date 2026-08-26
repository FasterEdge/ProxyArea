package main

// 配套 ProxyArea 使用的最小化测试服务器
// 用法: go run examples/testserver/main.go -addr=:8081
// 启动后,所有收到的请求会回显请求信息和参数,便于观察 ProxyArea 转发是否正确。

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	addr    = flag.String("addr", ":8081", "测试服务器监听地址")
	version = "1.0.20260826"
)

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/", handle)
	mux.HandleFunc("/test/get", handle)
	mux.HandleFunc("/test/post", handle)
	mux.HandleFunc("/test/put", handle)
	mux.HandleFunc("/test/all", handle)
	fmt.Printf("ProxyArea TestServer v%s 启动, 监听 %s\n", version, *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Println("服务退出:", err)
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[%s] %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.RequestURI())

	body, _ := io.ReadAll(r.Body)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// 归并 query / form 参数
	params := map[string][]string{}
	for k, v := range r.URL.Query() {
		params[k] = v
	}
	if err := r.ParseForm(); err == nil {
		for k, v := range r.PostForm {
			if _, exists := params[k]; !exists {
				params[k] = v
			}
		}
	}

	// header 转 map[string][]string
	headers := map[string][]string{}
	for k, v := range r.Header {
		headers[k] = v
	}

	resp := map[string]any{
		"method":      r.Method,
		"path":        r.URL.Path,
		"raw_query":   r.URL.RawQuery,
		"params":      params,
		"headers":     headers,
		"remote_addr": r.RemoteAddr,
		"body_size":   len(body),
	}
	if len(body) > 0 {
		resp["body"] = string(body)
	}
	_ = dumpJSON(w, resp)
}

// dumpJSON 极简 JSON 序列化(无外部依赖), 字符串转义
func dumpJSON(w http.ResponseWriter, m map[string]any) error {
	var b strings.Builder
	b.WriteString("{")
	first := true
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !first {
			b.WriteString(",")
		}
		first = false
		fmt.Fprintf(&b, "%q:", k)
		v := m[k]
		switch x := v.(type) {
		case string:
			fmt.Fprintf(&b, "%q", x)
		case int:
			fmt.Fprintf(&b, "%d", x)
		case map[string][]string:
			b.WriteString("{")
			first2 := true
			ks := make([]string, 0, len(x))
			for kk := range x {
				ks = append(ks, kk)
			}
			sort.Strings(ks)
			for _, kk := range ks {
				if !first2 {
					b.WriteString(",")
				}
				first2 = false
				fmt.Fprintf(&b, "%q:[", kk)
				for i, vv := range x[kk] {
					if i > 0 {
						b.WriteString(",")
					}
					fmt.Fprintf(&b, "%q", vv)
				}
				b.WriteString("]")
			}
			b.WriteString("}")
		default:
			fmt.Fprintf(&b, "%q", fmt.Sprint(x))
		}
	}
	b.WriteString("}\n")
	_, err := w.Write([]byte(b.String()))
	return err
}