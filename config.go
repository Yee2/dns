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
		Subnet  string `toml:"subnet"`
	} `toml:"upstreams"`
	Rules []struct {
		Name     string `toml:"name"`
		Action   string `toml:"action"`
		Upstream string `toml:"upstream"`
		TTL      int    `toml:"ttl"`
	} `toml:"rules"`
	Groups map[string]struct {
		Name string   `toml:"name"`
		List []string `toml:"list"`
	} `toml:"groups"`
	Records []CustomRecord `toml:"records"`
}{}

type CustomRecord struct {
	Name     string `toml:"name"`
	Type     string `toml:"type"`
	Class    string `toml:"class"`
	TTL      uint32 `toml:"ttl"`
	Context  string `toml:"context"`
	Priority uint16 `toml:"priority"`
}

func (r CustomRecord) RR() (rr dns.RR, e error) {
	if _, is := dns.IsDomainName(r.Name); !is {
		return nil, fmt.Errorf("invalid domain name:%s", r.Name)
	}
	if r.TTL == 0 {
		r.TTL = 3600
	}
	header := dns.RR_Header{Class: dns.ClassINET, Name: dns.Fqdn(r.Name), Ttl: r.TTL}
	if r.Class != "" {
		switch r.Class {
		case "IN":
		case "CS":
			header.Class = dns.ClassCSNET
		case "CH":
			header.Class = dns.ClassCHAOS
		case "HS":
			header.Class = dns.ClassHESIOD
		}
	}
	switch r.Type {
	case "A":
		ip := net.ParseIP(r.Context)
		if ip.To4() == nil {
			return nil, fmt.Errorf("bad IP address format:%s", r.Context)
		}
		ipNet := net.IPNet{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
		if ipNet.Contains(ip) {
			header.Ttl = 0
		}
		header.Rrtype = dns.TypeA
		return &dns.A{Hdr: header, A: ip.To4()}, nil
	case "AAAA":
		ip := net.ParseIP(r.Context)
		if ip.To16() == nil {
			return nil, fmt.Errorf("bad IP address format:%s", r.Context)
		}
		header.Rrtype = dns.TypeAAAA
		return &dns.A{Hdr: header, A: ip.To16()}, nil
	case "TXT":
		header.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: header, Txt: []string{r.Context}}, nil
	case "MX":
		header.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: header, Mx: r.Context, Preference: r.Priority}, nil
	case "NS":
		header.Rrtype = dns.TypeNS
		return &dns.NS{Hdr: header, Ns: r.Context}, nil
	case "CNAME":
		header.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: header, Target: r.Context}, nil
	default:
		return nil, fmt.Errorf("not supported:%s", r.Type)
	}
}
