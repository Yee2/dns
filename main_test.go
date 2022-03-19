package main

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
)

func questionA(domain string) dns.Question {
	return dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
}
func TestRuleSimple_Match(t *testing.T) {
	type fields struct {
		rule    string
		method  MatchType
		Handler Handler
	}
	prefixMatch := fields{
		rule:    "abc",
		method:  prefix,
		Handler: nil,
	}
	suffixMatch := fields{
		rule:    "xyz",
		method:  suffix,
		Handler: nil,
	}
	fqdnMatch := fields{
		rule:    "ddd",
		method:  fqdn,
		Handler: nil,
	}
	containMatch := fields{
		rule:    "abc",
		method:  contain,
		Handler: nil,
	}
	mustMatch := fields{
		method:  other,
		Handler: nil,
	}
	tests := []struct {
		name   string
		fields fields
		args   dns.Question
		want   bool
	}{
		{"prefixMatch", prefixMatch, questionA("abc"), true},
		{"prefixMatch", prefixMatch, questionA("abc.com"), true},
		{"prefixMatch", prefixMatch, questionA("www.abc.com"), false},
		{"prefixMatch", prefixMatch, questionA("www.xyz.com"), false},
		{"prefixMatch", prefixMatch, questionA("www.abc"), false},
		{"suffixMatch", suffixMatch, questionA("xyz"), true},
		{"suffixMatch", suffixMatch, questionA("xyz.com"), false},
		{"suffixMatch", suffixMatch, questionA("www.xyz.com"), false},
		{"suffixMatch", suffixMatch, questionA("www.abc.xyz"), true},
		{"fqdnMatch", fqdnMatch, questionA("ddd"), true},
		{"fqdnMatch", fqdnMatch, questionA("dddd"), false},
		{"fqdnMatch", fqdnMatch, questionA("ddd.ddd"), false},
		{"containMatch", containMatch, questionA("abc"), true},
		{"containMatch", containMatch, questionA("ab*"), false},
		{"containMatch", containMatch, questionA("xyz.com"), false},
		{"mustMatch", mustMatch, questionA(""), true},
		{"mustMatch", mustMatch, questionA("abc.com"), true},
		{"mustMatch", mustMatch, questionA("---"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &RuleSimple{
				rule:    tt.fields.rule,
				method:  tt.fields.method,
				Handler: tt.fields.Handler,
			}
			if got := p.Match(tt.args); got != tt.want {
				t.Errorf("Match() = %v:%v, want %v", got, tt.args, tt.want)
			}
		})
	}
}

func TestIPList_Contains(t *testing.T) {
	f, err := os.CreateTemp("", "cloudflare.txt")
	if err != nil {
		t.Log(err)
		return
	}
	_, err = f.WriteString(`173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
198.41.128.0/17
190.93.240.0/20
197.234.240.0/22
2606:4700::/32
2803:f800::/32
2405:b500::/32
103.31.4.0/22
108.162.192.0/18
2400:cb00::/32
2c0f:f248::/32
162.158.0.0/15
104.16.0.0/13
2405:8100::/32
2a06:98c0::/29
104.24.0.0/14
172.64.0.0/13
141.101.64.0/18
188.114.96.0/20
131.0.72.0/22`)
	if err != nil {
		t.Log(err)
		return
	}
	defer os.Remove(f.Name())
	list, err := NewIPList(f.Name(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		want bool
	}{
		{"127.0.0.1", false},
		{"8.8.8.8", false},
		{"1.0.0.1", false},
		{"190.93.240.255", true},
		{"2606:4700:3037::ffff:ffff", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rr dns.RR = &dns.AAAA{
				AAAA: net.ParseIP(tt.name),
			}
			if rr.(*dns.AAAA).AAAA.To4() != nil {
				rr = &dns.A{
					A: net.ParseIP(tt.name).To4(),
				}
			}
			if got := list.Contains(rr); got != tt.want {
				t.Errorf("Contains(%s) = %v, want %v", rr.String(), got, tt.want)
			}
		})
	}
}

func TestAdBlock_Match(t *testing.T) {
	f, err := os.CreateTemp("", "rules.txt")
	if err != nil {
		t.Log(err)
		return
	}
	f.WriteString(`
@@||.bad.example
one.example
||www.one.example
@@||bad.some.example
||some.example
||good.some.example
`)
	rules, err := NewAdBlock(f.Name(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		args string
		want bool
	}{
		{"bad.example", false},
		{"www.bad.example", false},
		{"good.some.example", true},
		{"good.good.some.example", true},
		{"one.example", true},
		{"www.one.example", true},
		{"w.w.w.one.example", false},
		{"bad.one.example", false},
		{"www.good.some.example", true},
	}
	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			if got := rules.Match(questionA(tt.args)); got != tt.want {
				t.Errorf("Match(%s) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestHttp3(t *testing.T) {
	transport := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			ServerName: "halfrost.com",
		},
	}
	defer transport.Close()
	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Get("https://halfrost.com/quic_start/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s\n", body)
}
