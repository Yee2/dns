package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func NewDoH(address string, method string, subnet string) (Provider, error) {
	switch method {
	case
		"",
		"doh",
		"doh-json",
		"doh-wireformat",
		"doh3",
		"doh3-json",
		"doh3-wireformat":
	default:

		return nil, fmt.Errorf("query method is not supported:%s", method)
	}
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{}
	if strings.HasPrefix(method, "doh3") {
		httpClient.Transport = &http3.RoundTripper{}
	} else {
		httpClient.Transport = &http.Transport{
			TLSClientConfig:    &tls.Config{ServerName: u.Hostname()},
			DisableCompression: true,
			MaxIdleConns:       1,
		}
	}
	var methodUint8 uint8
	if strings.HasSuffix(method, "json") {
		methodUint8 = 0
	} else {
		methodUint8 = 1
	}
	dnsClient := &DoH{address: u.String(), client: httpClient, method: methodUint8, subnet: subnet}
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
		} else {
			v6 := ip.IP.To16()
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

type DoH struct {
	address string
	client  *http.Client
	method  uint8
	subnet  string
	Extra   []dns.RR
}

func (that *DoH) name() string {
	return that.address
}

func (that *DoH) query(msg *dns.Msg) (*dns.Msg, error) {
	if that.method == 0 {
		return that.json(msg)
	} else {
		return that.wireformat(msg)
	}
}

func (that *DoH) wireformat(r *dns.Msg) (response *dns.Msg, err error) {
	if len(that.Extra) > 0 {
		r = r.Copy()
		r.Extra = append(r.Extra, that.Extra...)
	}
	raw, err := r.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns query:%w", err)
	}
	request, err := http.NewRequest("POST", that.address, bytes.NewBuffer(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/dns-message")
	request.Header.Add("accept", "application/dns-message")
	resp, err := that.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("dns-over-https:%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("dns-over-https error code %d", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("dns-over-https:%w", err)
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack dns response:%w", err)
	}
	return reply, nil
}
func (that *DoH) json(r *dns.Msg) (*dns.Msg, error) {
	question := r.Question[0]
	reply := new(dns.Msg).SetReply(r)
	u, err := url.Parse(that.address)
	if err != nil {
		return nil, err
	}
	args := u.Query()
	args.Set("name", question.Name)
	args.Set("type", strconv.Itoa(int(question.Qtype)))
	if that.subnet != "" {
		args.Set("edns_client_subnet", that.subnet)
	}
	u.RawQuery = args.Encode()
	logger.Debugf("dns json query:%s", u.String())
	request, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("request error:%s %s", question.Name, err)
	}
	request.Header.Add("accept", "application/dns-json")
	resp, err := that.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request error:%s %s", question.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("request error:%s %s", question.Name, err)
	}

	DoHresp := Response{}
	err = json.NewDecoder(resp.Body).Decode(&DoHresp)
	if err != nil {
		return nil, fmt.Errorf("error response data:%s %s", question.Name, err)
	}
	if DoHresp.Status != 0 {
		return nil, fmt.Errorf("request error:%s %s", question.Name, err)
	}
	for _, answer := range DoHresp.Answer {
		record := fmt.Sprintf("%s %d IN %s %s",
			question.Name, answer.TTL, dns.Type(answer.Type), answer.Data)
		if answer.Type == dns.TypeTXT {
			record = fmt.Sprintf(`%s %d IN %s "%s"`,
				question.Name, answer.TTL, dns.Type(answer.Type),
				strings.Replace(answer.Data, `"`, `\"`, -1))
		}
		logger.Debugf(record)
		rr, err := dns.NewRR(record)
		if err != nil {
			return nil, err
		}
		reply.Answer = append(reply.Answer, rr)
	}
	if len(reply.Answer) == 0 {
		reply.SetRcode(r, dns.RcodeServerFailure)
	}
	return reply, nil
}
