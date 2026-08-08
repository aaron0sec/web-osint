package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Report struct {
	Target       string            `json:"target"`
	URL          string            `json:"url"`
	GeneratedAt  time.Time         `json:"generated_at"`
	HTTP         HTTPInfo          `json:"http"`
	DNS          DNSInfo           `json:"dns"`
	TLS          *TLSInfo          `json:"tls,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
	Security     map[string]string `json:"security"`
	Robots       bool              `json:"robots_txt_found"`
	Sitemap      bool              `json:"sitemap_xml_found"`
	Errors       []string          `json:"errors,omitempty"`
}

type HTTPInfo struct {
	Status       string            `json:"status"`
	StatusCode   int               `json:"status_code"`
	FinalURL     string            `json:"final_url"`
	Server       string            `json:"server,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	ResponseTime int64             `json:"response_time_ms"`
}

type DNSInfo struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
}

type TLSInfo struct {
	Version     string    `json:"version"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Expires     time.Time `json:"expires"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	Valid       bool      `json:"valid"`
	SelfSigned  bool      `json:"self_signed"`
}

func main() {
	jsonOut := flag.Bool("json", false, "write JSON report")
	full := flag.Bool("full", false, "run all checks")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: web-osint [--json] [--full] <domain-or-url>")
		os.Exit(2)
	}

	target := flag.Arg(0)
	r := analyze(target, *full)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
	printReport(r)
}

func analyze(target string, full bool) Report {
	host := strings.TrimSpace(target)
	if !strings.Contains(host, "://") { host = "https://" + host }
	u, err := url.Parse(host)
	if err != nil || u.Hostname() == "" { return Report{Target: target, GeneratedAt: time.Now(), Errors: []string{"invalid target"}} }
	h := u.Hostname()
	r := Report{Target: h, GeneratedAt: time.Now(), Security: map[string]string{}}

	r.HTTP = inspectHTTP(host)
	r.DNS = inspectDNS(h)
	if strings.HasPrefix(r.HTTP.FinalURL, "https://") || strings.HasPrefix(host, "https://") {
		r.TLS = inspectTLS(h)
	}
	r.Technologies = detectTechnologies(r.HTTP.Server, r.HTTP.ContentType, r.HTTP.FinalURL)
	for k, v := range securityHeaders(lastHeaders) { r.Security[k] = v }

	if full {
		client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		r.Robots = resourceExists(client, "https://"+h+"/robots.txt") || resourceExists(client, "http://"+h+"/robots.txt")
		r.Sitemap = resourceExists(client, "https://"+h+"/sitemap.xml") || resourceExists(client, "http://"+h+"/sitemap.xml")
	}
	return r
}

var lastHeaders http.Header

func inspectHTTP(raw string) HTTPInfo {
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 { return errors.New("too many redirects") }
		return nil
	}}
	req, _ := http.NewRequest(http.MethodGet, raw, nil)
	req.Header.Set("User-Agent", "web-osint/0.1 (+https://github.com/aaron0sec/web-osint)")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil && strings.HasPrefix(raw, "https://") {
		raw = "http://" + strings.TrimPrefix(raw, "https://")
		req, _ = http.NewRequest(http.MethodGet, raw, nil)
		req.Header.Set("User-Agent", "web-osint/0.1")
		start = time.Now()
		resp, err = client.Do(req)
	}
	if err != nil { return HTTPInfo{Status: err.Error(), ResponseTime: time.Since(start).Milliseconds()} }
	defer resp.Body.Close()
	lastHeaders = resp.Header.Clone()
	return HTTPInfo{Status: resp.Status, StatusCode: resp.StatusCode, FinalURL: resp.Request.URL.String(), Server: resp.Header.Get("Server"), ContentType: resp.Header.Get("Content-Type"), ResponseTime: time.Since(start).Milliseconds()}
}

func inspectDNS(host string) DNSInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel()
	var d DNSInfo
	if ips, _ := net.DefaultResolver.LookupIP(ctx, "ip", host); len(ips) > 0 { for _, ip := range ips { if ip.To4() != nil { d.A = append(d.A, ip.String()) } else { d.AAAA = append(d.AAAA, ip.String()) } } }
	if mx, _ := net.DefaultResolver.LookupMX(ctx, host); len(mx) > 0 { for _, x := range mx { d.MX = append(d.MX, strings.TrimSuffix(x.Host, ".")) } }
	if ns, _ := net.DefaultResolver.LookupNS(ctx, host); len(ns) > 0 { for _, x := range ns { d.NS = append(d.NS, strings.TrimSuffix(x.Host, ".")) } }
	if txt, _ := net.DefaultResolver.LookupTXT(ctx, host); len(txt) > 0 { d.TXT = txt }
	return d
}

func inspectTLS(host string) *TLSInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second); defer cancel()
	d := net.Dialer{Timeout: 5*time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, "443"), &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil { return nil }
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 { return nil }
	c := state.PeerCertificates[0]
	valid := c.NotBefore.Before(time.Now()) && c.NotAfter.After(time.Now())
	verified := false
	if _, err := x509.SystemCertPool(); err == nil { verified = true }
	_ = ctx
	return &TLSInfo{Version: tlsVersion(state.Version), Subject: c.Subject.String(), Issuer: c.Issuer.String(), Expires: c.NotAfter, DNSNames: c.DNSNames, Valid: valid, SelfSigned: c.Issuer.String() == c.Subject.String() && !verified}
}

func tlsVersion(v uint16) string { switch v { case tls.VersionTLS13: return "TLS 1.3"; case tls.VersionTLS12: return "TLS 1.2"; default: return fmt.Sprintf("0x%x", v) } }

func detectTechnologies(server, contentType, finalURL string) []string {
	var out []string
	s := strings.ToLower(server + " " + contentType + " " + finalURL)
	patterns := map[string]string{"nginx":"nginx", "apache":"Apache", "cloudflare":"Cloudflare", "php":"PHP", "wordpress":"WordPress", "react":"React", "next.js":"Next.js"}
	for p, name := range patterns { if strings.Contains(s, p) { out = append(out, name) } }
	sort.Strings(out)
	return out
}

func securityHeaders(h http.Header) map[string]string {
	keys := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"}
	out := map[string]string{}
	for _, k := range keys { if v := h.Get(k); v != "" { out[k] = v } else { out[k] = "missing" } }
	return out
}

func resourceExists(c *http.Client, raw string) bool { req, _ := http.NewRequest(http.MethodHead, raw, nil); req.Header.Set("User-Agent", "web-osint/0.1"); resp, err := c.Do(req); if err != nil { return false }; resp.Body.Close(); return resp.StatusCode >= 200 && resp.StatusCode < 400 }

func printReport(r Report) {
	fmt.Printf("web-osint — public web intelligence\n\nTarget: %s\n\n", r.Target)
	fmt.Printf("HTTP\n  Status:       %s\n  Final URL:    %s\n  Server:       %s\n  Content-Type: %s\n  Response:     %d ms\n\n", r.HTTP.Status, r.HTTP.FinalURL, value(r.HTTP.Server), value(r.HTTP.ContentType), r.HTTP.ResponseTime)
	fmt.Println("DNS")
	fmt.Printf("  A:            %s\n  AAAA:         %s\n  MX:            %s\n  NS:            %s\n", join(r.DNS.A), join(r.DNS.AAAA), join(r.DNS.MX), join(r.DNS.NS))
	if r.TLS != nil { fmt.Printf("\nTLS\n  Version:       %s\n  Subject:       %s\n  Issuer:        %s\n  Expires:       %s\n  Valid:         %t\n", r.TLS.Version, r.TLS.Subject, r.TLS.Issuer, r.TLS.Expires.Format(time.RFC3339), r.TLS.Valid) }
	fmt.Printf("\nTechnologies: %s\n\nSecurity headers\n", join(r.Technologies))
	for k, v := range r.Security { fmt.Printf("  %-26s %s\n", k+":", v) }
	fmt.Printf("\nFull checks\n  robots.txt:   %t\n  sitemap.xml:  %t\n", r.Robots, r.Sitemap)
	fmt.Println("\nNote: traffic numbers are not inferred from response headers; authoritative visitor counts require analytics/server-side access or a third-party measurement source.")
}

func join(v []string) string { if len(v) == 0 { return "-" }; return strings.Join(v, ", ") }
func value(v string) string { if v == "" { return "-" }; return v }
var _ = regexp.MustCompile
