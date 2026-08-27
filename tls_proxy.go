package main

import (
    "flag"
    "log"
    "net/http"
)

// TLSProxy builds on the existing Proxy implementation and adds optional TLS support.
// It reuses the same Config struct defined in proxy.go; the extra flags are only
// parsed here and passed through the Config when applicable.
func main() {
    // Existing flags (kept for compatibility)
    var (
        addr            = flag.String("addr", ":8080", "listen address (host:port)")
        key             = flag.String("key", "", "shared secret for client authentication")
        allowHosts      = flag.String("allow-hosts", "", "comma‑separated whitelist of hostnames (empty = allow any)")
        requireAllow    = flag.Bool("require-allowlist", false, "reject requests if allow-hosts is empty")
        timeoutSec      = flag.Int("timeout", 30, "request timeout in seconds")
        insecureSkip    = flag.Bool("insecure-skip-verify", false, "skip TLS verification for upstream targets")
        maxRedirects    = flag.Int("max-redirects", 10, "maximum number of HTTP redirects to follow")
        disableRedirect = flag.Bool("disable-redirects", false, "if true, never follow redirects")
        // TLS specific flags
        certFile = flag.String("tls-cert", "", "path to PEM‑encoded TLS certificate (enables HTTPS mode when set)")
        keyFile  = flag.String("tls-key", "", "path to PEM‑encoded TLS private key (required with --tls-cert)")
    )
    flag.Parse()

    cfg := Config{
        Key:                *key,
        DefaultScheme:      "http",
        AllowHosts:         splitNonEmpty(*allowHosts),
        RequireAllowlist:   *requireAllow,
        Timeout:            time.Duration(*timeoutSec) * time.Second,
        InsecureSkipVerify: *insecureSkip,
        MaxRedirects:       *maxRedirects,
        DisableRedirects: *disableRedirect,
    }

    // Build proxy instance
    p, err := NewProxy(cfg)
    if err != nil {
        log.Fatalf("proxy init error: %v", err)
    }

    // Choose HTTP or HTTPS based on presence of cert/key
    if *certFile != "" || *keyFile != "" {
        if *certFile == "" || *keyFile == "" {
            log.Fatalf("both --tls-cert and --tls-key must be provided for TLS mode")
        }
        log.Printf("starting HTTPS proxy on %s", *addr)
        if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile, p.Handler()); err != nil {
            log.Fatalf("HTTPS server failed: %v", err)
        }
    } else {
        log.Printf("starting HTTP proxy on %s", *addr)
        if err := http.ListenAndServe(*addr, p.Handler()); err != nil {
            log.Fatalf("HTTP server failed: %v", err)
        }
    }
}

// splitNonEmpty splits a comma‑separated list and removes empty entries.
func splitNonEmpty(s string) []string {
    if s == "" {
        return nil
    }
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        if p = strings.TrimSpace(p); p != "" {
            out = append(out, p)
        }
    }
    return out
}
