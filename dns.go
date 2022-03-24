package main

import (
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"net"
)

func NewDNS(address, method string, subnet string) (Provider, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing address error:%w", err)
	}
	if port == "" {
		address = net.JoinHostPort(address, "53")
	}
	switch method {
	case "", "tcp", "udp", "tcp-tls":
	default:
		return nil, errors.Errorf("Unregistered query method:%s", method)
	}
	dnsClient := &DNS{address, &dns.Client{Net: method}, nil}
	if method == "tcp-tls" {
		dnsClient.client.TLSConfig = &tls.Config{ServerName: host}
	}
	if subnet != "" {
		_, ip, err := net.ParseCIDR(subnet)
		if err != nil {
			return dnsClient, nil
		}
		v4 := ip.IP.To4()
		if v4 != nil {
			e := new(dns.EDNS0_SUBNET)
			e.Code = dns.EDNS0SUBNET
			e.Family = 1
			e.SourceNetmask = 32
			e.SourceScope = 0
			e.Address = v4
			o := new(dns.OPT)
			o.Hdr.Name = "."
			o.Hdr.Rrtype = dns.TypeOPT
			o.Option = append(o.Option, e)
			dnsClient.Extra = append(dnsClient.Extra, o)
		}
		v6 := ip.IP.To16()
		if v6 != nil {
			e := new(dns.EDNS0_SUBNET)
			e.Code = dns.EDNS0SUBNET
			e.Family = 2
			e.SourceNetmask = 128
			e.SourceScope = 0
			e.Address = v6
			o := new(dns.OPT)
			o.Hdr.Name = "."
			o.Hdr.Rrtype = dns.TypeOPT
			o.Option = append(o.Option, e)
			dnsClient.Extra = append(dnsClient.Extra, o)
		}
	}

	return dnsClient, nil
}

type DNS struct {
	address string
	client  *dns.Client
	Extra   []dns.RR
}

func (s *DNS) name() string {
	return s.address
}

func (s *DNS) query(msg *dns.Msg) (reply *dns.Msg, err error) {
	if len(s.Extra) > 0 {
		msg = msg.Copy()
		msg.Extra = append(msg.Extra, s.Extra...)
	}
	reply, _, err = s.client.Exchange(msg, s.address)
	if err != nil {
		return nil, err
	}
	return reply, err
}
