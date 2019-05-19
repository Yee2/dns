package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
)

var config = struct {
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
	switch strings.ToUpper(r.Type) {
	case "A":
		ip := net.ParseIP(r.Context)
		return &dns.A{A: ip.To4()}, nil
	case "AAAA":
		ip := net.ParseIP(r.Context)
		return &dns.A{A: ip.To16()}, nil
	case "TXT":
		return &dns.TXT{Txt: []string{r.Context}}, nil
	case "MX":
		return &dns.MX{Mx: r.Context, Preference: r.Priority}, nil
	case "NS":
		return &dns.NS{Ns: r.Context}, nil
	case "CNAME":
		return &dns.CNAME{Target: r.Context}, nil
	default:
		return nil, fmt.Errorf("not supported:%s", r.Type)
	}
}

func (r lRecord) Match(address string) bool {
	if address == "other" {
		return true
	}
	array := strings.SplitN(r.Name, ":", 2)
	if len(array) != 2 {
		return false
	}
	switch array[0] {
	case "prefix":
		return strings.HasPrefix(address, array[1])
	case "suffix":
		return strings.HasSuffix(dns.Fqdn(address), dns.Fqdn(array[1]))
	case "contain":
		return strings.Contains(address, array[1])
	case "fqdn":
		return address == dns.Fqdn(array[1])
	default:
		logger.Warnf("Unknown match rule:%s", array[0])
		return false
	}
}
