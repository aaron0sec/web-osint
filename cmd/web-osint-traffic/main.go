package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type TrafficReport struct {
	Target       string           `json:"target"`
	GeneratedAt  time.Time        `json:"generated_at"`
	Sources      []TrafficSource  `json:"sources,omitempty"`
	Notes        []string         `json:"notes,omitempty"`
}

type TrafficSource struct {
	Provider string  `json:"provider"`
	Metric   string  `json:"metric"`
	Value    float64 `json:"value,omitempty"`
	Unit     string  `json:"unit,omitempty"`
	Period   string  `json:"period,omitempty"`
	Rank     int     `json:"rank,omitempty"`
	Bucket   string  `json:"bucket,omitempty"`
	SourceURL string `json:"source_url"`
	Estimated bool   `json:"estimated"`
	Available bool   `json:"available"`
	Error    string  `json:"error,omitempty"`
}

var client = &http.Client{Timeout: 15 * time.Second}

func main() {
	jsonOut := flag.Bool("json", false, "write JSON report")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: web-osint-traffic [--json] <domain>")
		os.Exit(2)
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(flag.Arg(0)), "."))
	r := TrafficReport{Target: domain, GeneratedAt: time.Now()}
	if key := os.Getenv("SIMILARWEB_API_KEY"); key != "" {
		r.Sources = append(r.Sources, similarweb(domain, key))
	} else {
		r.Sources = append(r.Sources, TrafficSource{Provider: "Similarweb", Metric: "visits", SourceURL: "https://developers.similarweb.com/reference/visits", Estimated: true, Error: "SIMILARWEB_API_KEY is not configured"})
		r.Notes = append(r.Notes, "Similarweb traffic values are third-party estimates, not authoritative server analytics.")
	}
	if token := os.Getenv("CLOUDFLARE_API_TOKEN"); token != "" {
		r.Sources = append(r.Sources, cloudflareRank(domain, token))
	} else {
		r.Sources = append(r.Sources, TrafficSource{Provider: "Cloudflare Radar", Metric: "domain popularity rank", SourceURL: "https://developers.cloudflare.com/api/resources/radar/subresources/ranking/subresources/domain/methods/get", Error: "CLOUDFLARE_API_TOKEN is not configured"})
	}
	if *jsonOut {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return
	}
	printReport(r)
}

func similarweb(domain, key string) TrafficSource {
	u := "https://api.similarweb.com/v1/website/" + url.PathEscape(domain) + "/total-traffic-and-engagement/visits?api_key=" + url.QueryEscape(key) + "&country=world&granularity=monthly"
	resp, err := client.Get(u)
	if err != nil { return TrafficSource{Provider: "Similarweb", Metric: "visits", SourceURL: "https://developers.similarweb.com/reference/visits", Estimated: true, Error: err.Error()} }
	defer resp.Body.Close()
	if resp.StatusCode >= 400 { return TrafficSource{Provider: "Similarweb", Metric: "visits", SourceURL: "https://developers.similarweb.com/reference/visits", Estimated: true, Error: fmt.Sprintf("HTTP %d", resp.StatusCode)} }
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil { return TrafficSource{Provider: "Similarweb", Metric: "visits", SourceURL: "https://developers.similarweb.com/reference/visits", Estimated: true, Error: err.Error()} }
	points := extractVisitPoints(b)
	if len(points) == 0 { return TrafficSource{Provider: "Similarweb", Metric: "visits", SourceURL: "https://developers.similarweb.com/reference/visits", Estimated: true, Error: "response contained no visit data"} }
	sort.Slice(points, func(i, j int) bool { return points[i].Date > points[j].Date })
	return TrafficSource{Provider: "Similarweb", Metric: "visits", Value: points[0].Visits, Unit: "visits", Period: points[0].Date, SourceURL: "https://developers.similarweb.com/reference/visits", Estimated: true, Available: true}
}

type visitPoint struct { Date string; Visits float64 }

func extractVisitPoints(b []byte) []visitPoint {
	var root any
	if json.Unmarshal(b, &root) != nil { return nil }
	var out []visitPoint
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x { walk(item) }
		case map[string]any:
			var date string
			for _, k := range []string{"date", "period", "month"} { if s, ok := x[k].(string); ok { date = s; break } }
			if raw, ok := x["visits"]; ok { if n, ok := number(raw); ok && date != "" { out = append(out, visitPoint{Date: date, Visits: n}) } }
			for _, child := range x { walk(child) }
		}
	}
	walk(root)
	return out
}

func number(v any) (float64, bool) {
	switch n := v.(type) { case float64: return n, true; case json.Number: f, e := n.Float64(); return f, e == nil; case map[string]any: for _, k := range []string{"value", "visits"} { if x, ok := n[k]; ok { return number(x) } } }
	return 0, false
}

func cloudflareRank(domain, token string) TrafficSource {
	u := "https://api.cloudflare.com/client/v4/radar/ranking/domain/" + url.PathEscape(domain) + "?rankingType=POPULAR&includeTopLocations=false"
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil { return TrafficSource{Provider: "Cloudflare Radar", Metric: "domain popularity rank", SourceURL: "https://developers.cloudflare.com/api/resources/radar/subresources/ranking/subresources/domain/methods/get", Error: err.Error()} }
	defer resp.Body.Close()
	if resp.StatusCode >= 400 { return TrafficSource{Provider: "Cloudflare Radar", Metric: "domain popularity rank", SourceURL: "https://developers.cloudflare.com/api/resources/radar/subresources/ranking/subresources/domain/methods/get", Error: fmt.Sprintf("HTTP %d", resp.StatusCode)} }
	var d struct { Success bool `json:"success"`; Result struct { Details struct { Rank int `json:"rank"`; Bucket string `json:"bucket"` } `json:"details_0"` } `json:"result"` }
	if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&d) != nil || !d.Success { return TrafficSource{Provider: "Cloudflare Radar", Metric: "domain popularity rank", SourceURL: "https://developers.cloudflare.com/api/resources/radar/subresources/ranking/subresources/domain/methods/get", Error: "invalid API response"} }
	return TrafficSource{Provider: "Cloudflare Radar", Metric: "domain popularity rank", Rank: d.Result.Details.Rank, Bucket: d.Result.Details.Bucket, SourceURL: "https://developers.cloudflare.com/api/resources/radar/subresources/ranking/subresources/domain/methods/get", Available: d.Result.Details.Rank > 0 || d.Result.Details.Bucket != ""}
}

func printReport(r TrafficReport) {
	fmt.Printf("web-osint-traffic — public traffic intelligence\n\nTarget: %s\n\n", r.Target)
	for _, s := range r.Sources {
		fmt.Printf("[%s]\n  Metric:  %s\n", s.Provider, s.Metric)
		if s.Available { if s.Value > 0 { fmt.Printf("  Value:   %.0f %s\n", s.Value, s.Unit) }; if s.Period != "" { fmt.Printf("  Period:  %s\n", s.Period) }; if s.Rank > 0 { fmt.Printf("  Rank:    %d\n", s.Rank) }; if s.Bucket != "" { fmt.Printf("  Bucket:  %s\n", s.Bucket) } } else { fmt.Printf("  Status:  unavailable\n") }
		if s.Estimated { fmt.Printf("  Type:    estimated\n") }
		if s.Error != "" { fmt.Printf("  Error:   %s\n", s.Error) }
		fmt.Printf("  Source:  %s\n\n", s.SourceURL)
	}
	for _, n := range r.Notes { fmt.Printf("Note: %s\n", n) }
}
