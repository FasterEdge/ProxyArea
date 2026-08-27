package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type seenRequest struct {
	Method, Body, ContentType string
	Header                    http.Header
	URL                       *url.URL
}

func testProxy(t *testing.T, cfg Config) (*httptest.Server, <-chan seenRequest) {
	t.Helper()
	seen := make(chan seenRequest, 20)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- seenRequest{r.Method, string(body), r.Header.Get("Content-Type"), r.Header.Clone(), r.URL}
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	cfg.Transport = http.DefaultTransport
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(p.Handler())
	t.Cleanup(proxy.Close)
	return proxy, seen
}

func do(t *testing.T, method, endpoint string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRoutesAndBodyPreservation(t *testing.T) {
	methods := map[string]string{"/get": "GET", "/post": "POST", "/proxy": "PROPFIND", "/proxy/": "PROPFIND", "/proxy/get": "GET", "/proxy/post": "POST", "/proxy/put": "PUT", "/proxy/patch": "PATCH", "/proxy/delete": "DELETE", "/proxy/head": "HEAD", "/proxy/options": "OPTIONS"}
	for path, want := range methods {
		t.Run(strings.ReplaceAll(path, "/", "_"), func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				w.Header().Set("X-Seen", r.Method+":"+base64.StdEncoding.EncodeToString(b))
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte("ok"))
				}
			}))
			defer up.Close()
			p, _ := NewProxy(Config{})
			proxy := httptest.NewServer(p.Handler())
			defer proxy.Close()
			resp := do(t, "PROPFIND", proxy.URL+path+"?url="+url.QueryEscape(up.URL), bytes.NewReader([]byte{0, 1, 2, 255}), map[string]string{"Content-Type": "application/octet-stream"})
			defer resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("X-Seen") != want+":"+base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255}) {
				t.Fatalf("status=%d seen=%q", resp.StatusCode, resp.Header.Get("X-Seen"))
			}
		})
	}
	p, _ := NewProxy(Config{})
	proxy := httptest.NewServer(p.Handler())
	defer proxy.Close()
	if resp := do(t, "GET", proxy.URL+"/proxy/nope?url=x", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("unknown=%d", resp.StatusCode)
	}
}

func TestControlSourcesAndAuthentication(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s|%s", r.URL.Query().Get("x"), b)
	}))
	defer up.Close()
	p, _ := NewProxy(Config{Key: "secret"})
	proxy := httptest.NewServer(p.Handler())
	defer proxy.Close()
	cases := []struct {
		name, path, ct, body string
		headers              map[string]string
		status               int
	}{
		{"bearer", "?url=" + url.QueryEscape(up.URL) + "&key=bad", "application/json", `{"url":"business"}`, map[string]string{"Authorization": "Bearer secret"}, 200},
		{"x-key", "?url=" + url.QueryEscape(up.URL), "text/plain", "raw", map[string]string{"X-Proxy-Key": "secret"}, 200},
		{"header-empty-no-fallback", "?url=" + url.QueryEscape(up.URL) + "&key=secret", "", "", map[string]string{"Authorization": ""}, 401},
		{"query-wins", "?url=" + url.QueryEscape(up.URL) + "&key=secret&params=x%3Dquery", "application/x-www-form-urlencoded", "url=bad&params=x%3Dform", nil, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.headers
			if h == nil {
				h = map[string]string{}
			}
			if tc.ct != "" {
				h["Content-Type"] = tc.ct
			}
			resp := do(t, "POST", proxy.URL+"/proxy"+tc.path, strings.NewReader(tc.body), h)
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d %s", resp.StatusCode, b)
			}
		})
	}
}

func TestFormMultipartAndEnvelope(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s|%s", r.Header.Get("Content-Type"), b)
	}))
	defer up.Close()
	p, _ := NewProxy(Config{})
	proxy := httptest.NewServer(p.Handler())
	defer proxy.Close()
	form := "url=" + url.QueryEscape(up.URL) + "&name=alice"
	resp := do(t, "POST", proxy.URL+"/post", strings.NewReader(form), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), form) {
		t.Fatalf("form body lost: %s", b)
	}
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	_ = mw.WriteField("url", up.URL)
	f, _ := mw.CreateFormFile("file", "a.bin")
	_, _ = f.Write([]byte{0, 255})
	_ = mw.Close()
	raw := append([]byte(nil), mb.Bytes()...)
	resp = do(t, "POST", proxy.URL+"/proxy", bytes.NewReader(raw), map[string]string{"Content-Type": mw.FormDataContentType()})
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(b, []byte("a.bin")) {
		t.Fatalf("multipart lost")
	}
	encodings := []struct{ enc, body, want, ct string }{{"none", "null", "", ""}, {"json", `{"a":1}`, `{"a":1}`, "application/json"}, {"text", `"hello"`, "hello", "text/plain"}, {"base64", `"AAH/"`, string([]byte{0, 1, 255}), "application/octet-stream"}}
	for _, x := range encodings {
		t.Run(x.enc, func(t *testing.T) {
			env := fmt.Sprintf(`{"url":%q,"encoding":%q,"body":%s`, up.URL, x.enc, x.body)
			if x.ct != "" {
				env += fmt.Sprintf(`,"contentType":%q`, x.ct)
			}
			env += "}"
			resp := do(t, "POST", proxy.URL+"/proxy", strings.NewReader(env), map[string]string{"Content-Type": envelopeType})
			out, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(out), x.want) {
				t.Fatalf("%d %q", resp.StatusCode, out)
			}
		})
	}
	for _, bad := range []string{`{"url":"x","unknown":1}`, `{"url":"x","encoding":"base64","body":"!"}`, `{"url":"x","encoding":"wat"}`, `{"url":"x","encoding":"none","contentType":"text/plain"}`, `{"url":"x"} {}`} {
		resp := do(t, "POST", proxy.URL+"/proxy", strings.NewReader(bad), map[string]string{"Content-Type": envelopeType})
		if resp.StatusCode != 400 {
			t.Fatalf("bad envelope status=%d", resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestURLValidationAndParams(t *testing.T) {
	c := controls{url: value{"example.com/a%252Fb?q=a+b", true}, params: value{"x=1&x=2&u=张三", true}}
	u, err := buildTargetURL(c, "http")
	if err != nil {
		t.Fatal(err)
	}
	if u.EscapedPath() != "/a%252Fb" || len(u.Query()["x"]) != 2 || u.Query().Get("q") != "a b" {
		t.Fatalf("url=%s", u)
	}
	for _, bad := range []string{"ftp://example.com", "http://u:p@example.com", "http://example.com:bad", "http://example.com:0", "http://example.com:65536", "http:///x", "http://x\nHost:y"} {
		if _, err := buildTargetURL(controls{url: value{bad, true}}, "http"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := buildTargetURL(controls{url: value{"example.com", true}, https: value{"bad", true}}, "http"); err == nil {
		t.Fatal("accepted invalid https")
	}
}

func TestHeadersAllowlistRedirectAndErrors(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Connection", "X-Drop")
		w.Header().Set("X-Drop", "bad")
		w.Header().Add("X-Multi", "a")
		w.Header().Add("X-Multi", "b")
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()
	host := strings.Split(strings.TrimPrefix(up.URL, "http://"), ":")[0]
	p, _ := NewProxy(Config{Key: "s", AllowHosts: []string{strings.ToUpper(host)}})
	proxy := httptest.NewServer(p.Handler())
	defer proxy.Close()
	resp := do(t, "GET", proxy.URL+"/proxy?url="+url.QueryEscape(up.URL), nil, map[string]string{"Authorization": "Bearer s", "Connection": "X-Secret", "X-Secret": "bad", "X-End": "ok"})
	defer resp.Body.Close()
	if got.Get("Authorization") != "" || got.Get("X-Secret") != "" || (got.Get("X-End") != "ok" && got.Get("X-End") != "") {
		t.Fatalf("leak=%v", got)
	}
	if resp.Header.Get("X-Drop") != "" || len(resp.Header.Values("X-Multi")) != 2 {
		t.Fatalf("response headers=%v", resp.Header)
	}
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer blocked.Close()
	blockedURL, _ := url.Parse(blocked.URL)
	redirectTarget := "http://localhost:" + blockedURL.Port()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, redirectTarget, http.StatusFound) }))
	defer redir.Close()
	allowedURL, _ := url.Parse(redir.URL)
	p2, _ := NewProxy(Config{AllowHosts: []string{allowedURL.Hostname()}})
	ps := httptest.NewServer(p2.Handler())
	defer ps.Close()
	resp = do(t, "GET", ps.URL+"/proxy?url="+url.QueryEscape(redir.URL), nil, nil)
	if resp.StatusCode != 502 {
		t.Fatalf("redirect status=%d", resp.StatusCode)
	}
	resp.Body.Close()
	p3, _ := NewProxy(Config{Timeout: 10 * time.Millisecond})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(50 * time.Millisecond) }))
	defer slow.Close()
	px := httptest.NewServer(p3.Handler())
	defer px.Close()
	resp = do(t, "GET", px.URL+"/proxy?url="+url.QueryEscape(slow.URL), nil, nil)
	if resp.StatusCode != 504 {
		t.Fatalf("timeout=%d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestLargeOrdinaryBodyStreamsWithoutTruncation(t *testing.T) {
	const extra = 12345
	want := maxControlBody + extra
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Error(err)
		}
		_, _ = fmt.Fprint(w, n)
	}))
	defer up.Close()
	p, _ := NewProxy(Config{})
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "POST", s.URL+"/proxy?url="+url.QueryEscape(up.URL), strings.NewReader(strings.Repeat("x", want)), map[string]string{"Content-Type": "application/octet-stream"})
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(data) != strconv.Itoa(want) {
		t.Fatalf("status=%d body=%q", resp.StatusCode, data)
	}
}

func TestGenericRouteConcurrentMethods(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Method) }))
	defer up.Close()
	p, _ := NewProxy(Config{})
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	methods := []string{"GET", "POST", "PATCH", "DELETE", "PROPFIND"}
	var wg sync.WaitGroup
	errCh := make(chan string, len(methods)*20)
	for i := 0; i < 20; i++ {
		for _, method := range methods {
			wg.Add(1)
			go func(method string) {
				defer wg.Done()
				resp, err := http.DefaultClient.Do(mustRequest(method, s.URL+"/proxy?url="+url.QueryEscape(up.URL), nil))
				if err != nil {
					errCh <- err.Error()
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) != method {
					errCh <- method + "->" + string(body)
				}
			}(method)
		}
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func mustRequest(method, endpoint string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		panic(err)
	}
	return req
}

func TestEnvelopeSanitizationAndResponseCredentials(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "" {
			t.Errorf("stale content encoding: %q", r.Header.Get("Content-Encoding"))
		}
		w.Header().Set("Authorization", "response-auth")
		w.Header().Set("X-Proxy-Key", "response-key")
	}))
	defer up.Close()
	p, _ := NewProxy(Config{})
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	env := fmt.Sprintf(`{"url":%q,"encoding":"text","body":"hello"}`, up.URL)
	resp := do(t, "POST", s.URL+"/proxy", strings.NewReader(env), map[string]string{"Content-Type": envelopeType, "Content-Encoding": "gzip"})
	defer resp.Body.Close()
	if resp.Header.Get("Authorization") != "response-auth" || resp.Header.Get("X-Proxy-Key") != "response-key" {
		t.Fatalf("response credentials stripped: %v", resp.Header)
	}
}

func TestRedirectPolicyAndAllowlistSafety(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/final" {
			_, _ = w.Write(body)
			return
		}
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(http.StatusFound)
	}))
	defer up.Close()
	final := strings.TrimPrefix(up.URL, "http://") + "/final"
	redirEndpoint := up.URL + "?to=" + url.QueryEscape("http://"+final)

	for _, tc := range []struct {
		name string
		cfg  Config
		want int
	}{{"default-follows", Config{}, 200}, {"disabled", Config{DisableRedirects: true}, 302}} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := NewProxy(tc.cfg)
			s := httptest.NewServer(p.Handler())
			defer s.Close()
			client := http.DefaultClient
			if tc.cfg.DisableRedirects {
				client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			}
			req, _ := http.NewRequest("GET", s.URL+"/proxy?url="+url.QueryEscape(redirEndpoint), nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status=%d", resp.StatusCode)
			}
		})
	}
	if _, err := NewProxy(Config{MaxRedirects: -1}); err == nil {
		t.Fatal("accepted negative MaxRedirects")
	}
	if _, err := NewProxy(Config{MaxRedirects: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewProxy(Config{RequireAllowlist: true}); err == nil {
		t.Fatal("safe mode accepted empty allowlist; this would expose metadata endpoints")
	}
}

func TestOversize(t *testing.T) {
	p, _ := NewProxy(Config{})
	s := httptest.NewServer(p.Handler())
	defer s.Close()
	resp := do(t, "POST", s.URL+"/proxy", strings.NewReader(strings.Repeat("x", maxControlBody+1)), map[string]string{"Content-Type": envelopeType})
	defer resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}
func TestJSONErrorEncoding(t *testing.T) {
	r := httptest.NewRecorder()
	writeJSON(r, 400, "bad \" value")
	var v map[string]string
	if err := json.Unmarshal(r.Body.Bytes(), &v); err != nil || v["error"] != "bad \" value" {
		t.Fatalf("%s %v", r.Body.String(), err)
	}
}
