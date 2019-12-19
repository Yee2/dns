package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
)

var config = struct {
	Path    string
	Servers []struct {
		Type    string `toml:"type"`
		Address string `toml:"address"`
	} `toml:"listen"`
	Upstreams []struct {
		Name    string `toml:"name"`
		Method  string `toml:"method"`
		Address string `toml:"address"`
	} `toml:"upstreams"`
	Rules []struct {
		Name     string `toml:"name"`
		Action   string `toml:"action"`
		Upstream string `toml:"upstream"`
	} `toml:"rules"`
	Groups map[string]struct {
		Name string   `toml:"name"`
		List []string `toml:"list"`
	} `toml:"groups"`
	Records []lRecord `toml:"records"`
}{}

type lRecord struct {
	Name     string `toml:"name"`
	Type     string `toml:"type"`
	TTL      uint32 `toml:"ttl"`
	Context  string `toml:"context"`
	Priority uint16 `toml:"priority"`
}

func (r lRecord) RR() (rr dns.RR, e error) {
	if _, is := dns.IsDomainName(r.Name); !is {
		return nil, fmt.Errorf("invalid domain name:%s", r.Name)
	}
	switch r.Type {
	case "A":
		ip := net.ParseIP(r.Context)
		return &dns.A{Hdr: dns.RR_Header{Ttl: r.TTL}, A: ip.To4()}, nil
	case "AAAA":
		ip := net.ParseIP(r.Context)
		return &dns.A{Hdr: dns.RR_Header{Ttl: r.TTL}, A: ip.To16()}, nil
	case "TXT":
		return &dns.TXT{Hdr: dns.RR_Header{Ttl: r.TTL}, Txt: []string{r.Context}}, nil
	case "MX":
		return &dns.MX{Hdr: dns.RR_Header{Ttl: r.TTL}, Mx: r.Context, Preference: r.Priority}, nil
	case "NS":
		return &dns.NS{Hdr: dns.RR_Header{Ttl: r.TTL}, Ns: r.Context}, nil
	case "CNAME":
		return &dns.CNAME{Hdr: dns.RR_Header{Ttl: r.TTL}, Target: r.Context}, nil
	default:
		return nil, fmt.Errorf("not supported:%s", r.Type)
	}
}
