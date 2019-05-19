package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	logger = &logrus.Logger{
		Out:       os.Stdout,
		Formatter: &logrus.TextFormatter{ForceColors: true},
		Level:     logrus.InfoLevel,
	}
)

type Response struct {
	Status   int
	TC       bool
	RD       bool
	RA       bool
	AD       bool
	CD       bool
	Answer   []Record
	Question []Record
	Comment  string
}
type Record struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}
type Rule interface {
	Match(address string) bool
	dns.Handler
}
type DNSwriter struct {
	origin dns.ResponseWriter
	msg    *dns.Msg
}

func (r *DNSwriter) LocalAddr() net.Addr {
	return r.origin.LocalAddr()
}

func (r *DNSwriter) RemoteAddr() net.Addr {
	return r.origin.RemoteAddr()
}

func (r *DNSwriter) WriteMsg(msg *dns.Msg) error {
	r.msg.Insert(msg.Answer)
	logger.Debugf("answer:%s", msg.Answer[0].String())
	return nil
}

func (*DNSwriter) Write([]byte) (int, error) {
	panic("implement me")
}

func (r *DNSwriter) Close() error {
	return nil
}

func (*DNSwriter) TsigStatus() error {
	panic("implement me")
}

func (*DNSwriter) TsigTimersOnly(bool) {
	panic("implement me")
}

func (*DNSwriter) Hijack() {
	panic("implement me")
}
func (r *DNSwriter) Finish() error {
	err := r.origin.WriteMsg(r.msg)
	if err != nil {
		return err
	}
	return r.origin.Close()
}

func main() {
	app := &cli.App{Name: "DNS", Action: run, Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/my-dns/config.toml",
			Usage: "set the config.toml file path",
		},
	}}
	err := app.Run(os.Args)
	if err != nil {
		logger.Error(err)
		os.Exit(-1)
	}
}

type Rules []Rule

func (rules Rules) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		//TODO: 记录错误信息
		_ = w.WriteMsg(new(dns.Msg).SetRcodeFormatError(r))
		return
	}
	logger.Debugf("handle:%s", r.Question[0].Name)
	writer := &DNSwriter{origin: w, msg: r.Copy().SetReply(r)}
	defer writer.Finish()
	// TODO: 分解问题，优化成多个问题合并在一起
LOOP:
	for _, q := range r.Question {
		// 第一步 查找 config.Records
		logger.Debugf("query:%s", q.String())
		for _, record := range config.Records {
			if strings.ToUpper(record.Type) != dns.Type(q.Qtype).String() {
				continue
			}
			if record.Match(q.Name) {
				rr, err := record.RR()
				msg := new(dns.Msg)
				if err != nil {
					// TODO:
				} else {
					rr.Header().Ttl = record.TTL
					if rr.Header().Ttl == 0 {
						rr.Header().Ttl = 3600
					}
					rr.Header().Name = q.Name
					rr.Header().Rrtype = q.Qtype
					msg.Answer = []dns.RR{rr}
					writer.WriteMsg(msg)
					continue LOOP
				}
			}
		}
		// 第二步 从外部查询记录
		for _, item := range rules {
			if item.Match(q.Name) {
				c := r.Copy()
				c.Question = []dns.Question{q}
				item.ServeDNS(writer, c)
				return
			}
		}
	}
}
func run(ctx *cli.Context) error {
	data, err := ioutil.ReadFile(ctx.String("config"))
	if err != nil {
		return errors.Wrapf(err, "Failed to read configuration file(%s)", ctx.String("config"))
	}

	if err := toml.Unmarshal(data, &config); err != nil {
		return errors.Wrapf(err, "Unable to parse configuration file(%s)", ctx.String("config"))
	}
	logger.Debugf("%+v", config)
	handles := make(map[string]dns.Handler)
	reject := &Reject{}
	for _, upstream := range config.Upstreams {
		switch upstream.Method {
		case "doh-json":
			handle, err := NewDoH(upstream.Address, upstream.Method)
			if err != nil {
				return err
			}
			handles[upstream.Name] = handle
		case "doh-wireformat":
			handle, err := NewDoH(upstream.Address, upstream.Method)
			if err != nil {
				return err
			}
			handles[upstream.Name] = handle
		case "udp":
			handle, err := NewDNS(upstream.Address, upstream.Method)
			if err != nil {
				return err
			}
			handles[upstream.Name] = handle
		case "tcp":
			handle, err := NewDNS(upstream.Address, upstream.Method)
			if err != nil {
				return err
			}
			handles[upstream.Name] = handle
		case "tcp-tls":
			handle, err := NewDNS(upstream.Address, upstream.Method)
			if err != nil {
				return err
			}
			handles[upstream.Name] = handle
		default:
			return errors.Errorf("Unregistered query method:%s", upstream.Method)
		}
	}
	rules := make(Rules, 0)
	for _, rule := range config.Rules {
		var handler dns.Handler
		var ok bool
		if rule.Action == "reject" {
			handler = reject
		} else {
			handler, ok = handles[rule.Upstream]
			if !ok {
				return errors.Errorf("No matching superior DNS server was found:%s", rule.Upstream)
			}
		}
		array := strings.SplitN(rule.Name, ":", 2)
		if len(array) < 2 && rule.Name != "other" {
			return errors.Errorf("Match rule syntax error:%s", rule.Name)
		}
		switch array[0] {
		case "prefix":
			rules = append(rules, &RuleSimple{rule: array[1], method: prefix, Handler: handler})
		case "suffix":
			rules = append(rules, &RuleSimple{rule: array[1], method: suffix, Handler: handler})
		case "contain":
			rules = append(rules, &RuleSimple{rule: array[1], method: contain, Handler: handler})
		case "fqdn":
			rules = append(rules, &RuleSimple{rule: array[1], method: fqdn, Handler: handler})
		case "other":
			rules = append(rules, &RuleSimple{method: other, Handler: handler})
		case "group":
			rule, err := NewRuleGroup(array[1], handler)
			if err != nil {
				return err
			}
			rules = append(rules, rule)
		default:
			return errors.Errorf("Unregistered match:%s", rule.Name)
		}
	}
	servers := make([]*dns.Server, 0, len(config.Servers))
	errorChanel := make(chan error)

	for _, serverInfo := range config.Servers {
		server := &dns.Server{Addr: serverInfo.Address, Net: serverInfo.Type, Handler: rules}
		logger.Infof("serve at %s:%s", serverInfo.Type, serverInfo.Address)

		go func() {
			if err := server.ListenAndServe(); err != nil {
				errorChanel <- err
			}
		}()
		servers = append(servers, server)
	}
	err = <-errorChanel
	return err
}
func NewDoH(address string, method string) (*DoH, error) {
	if method != "doh-json" && method != "doh-wireformat" && method != "" {
		return nil, errors.Errorf("错误的方式")
	}
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{ServerName: u.Hostname()},
		DisableCompression: true,
		MaxIdleConns:       1,
	}
	var methodUint8 uint8
	if method == "doh-wireformat" {
		methodUint8 = 1
	}
	return &DoH{address: u.String(), client: &http.Client{Transport: transport}, method: methodUint8}, nil
}

type DoH struct {
	address string
	client  *http.Client
	method  uint8
}

func (that *DoH) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if that.method == 0 {
		that.json(w, r)
	} else {
		that.wireformat(w, r)
	}
}

func (that *DoH) wireformat(w dns.ResponseWriter, r *dns.Msg) {
	raw, err := r.Pack()
	if err != nil {
		logger.Warnf("failed to pack dns query:%s", err)
		w.WriteMsg(new(dns.Msg).SetRcodeFormatError(r))
		return
	}
	request, err := http.NewRequest("POST", that.address, bytes.NewBuffer(raw))
	request.Header.Add("Content-Type", "application/dns-udpwireformat")
	request.Header.Add("accept", "application/dns-message")
	resp, err := that.client.Do(request)
	if err != nil {
		logger.Warn(errors.Wrap(err, "dns-over-https"))
		w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}
	if resp.StatusCode != 200 {
		logger.Warn(errors.Wrapf(err, "dns-over-https error code %d", resp.StatusCode))
		w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Warn(errors.Wrapf(err, "dns-over-https"))
		w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		logger.Warn(errors.Wrapf(err, "failed to unpack dns response"))
		w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
		return
	}
	reply.SetReply(r)
	for _, answer := range reply.Answer {
		logger.Info(answer)
	}
	w.WriteMsg(reply)
}
func (that *DoH) json(w dns.ResponseWriter, r *dns.Msg) {
	records := make([]dns.RR, 0)
	for _, question := range r.Question {
		u := fmt.Sprintf("%s?name=%s&type=%d", that.address,
			url.QueryEscape(question.Name),
			question.Qtype,
		)
		request, err := http.NewRequest("GET", u, nil)
		if err != nil {
			logger.Warn(err)
			continue
		}
		request.Header.Add("accept", "application/dns-json")
		resp, err := that.client.Do(request)
		if err != nil {
			logger.Warn(errors.Wrap(err, "dns-over-https"))
			continue
		}
		if resp.StatusCode != 200 {
			logger.Warn(errors.Wrapf(err, "dns-over-https error code %d", resp.StatusCode))
			continue
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Warn(errors.Wrap(err, "dns-over-https read error"))
			continue
		}
		DoHresp := &Response{}
		err = json.Unmarshal(data, DoHresp)
		if err != nil {
			logger.Warn(errors.Wrap(err, "dns-over-https unmarshal fail"))
			continue
		}
		if DoHresp.Status != 0 {
			logger.Warn(errors.Errorf("dns-over-https error:%s", DoHresp.Comment))
			continue
		}
		for _, answer := range DoHresp.Answer {
			record := fmt.Sprintf("%s %d IN %s %s",
				question.Name, answer.TTL, dns.Type(answer.Type), answer.Data)
			if answer.Type == dns.TypeTXT {
				record = fmt.Sprintf(`%s %d IN %s "%s"`,
					question.Name, answer.TTL, dns.Type(answer.Type),
					strings.Replace(answer.Data, `"`, `\"`, 0))
			}
			logger.Info(record)
			rr, err := dns.NewRR(record)
			if err != nil {
				logger.Warn(errors.Wrapf(err, "dns-over-https error answer:%s",
					fmt.Sprintf("%s %d IN %s %s",
						question.Name, answer.TTL, dns.Type(answer.Type), answer.Data)))
				continue
			}
			records = append(records, rr)
		}
		resp.Body.Close()
	}

	reply := &dns.Msg{Answer: records}
	if len(records) == 0 {
		reply.SetRcode(r, dns.RcodeServerFailure)
	} else {
		reply.SetReply(r)
	}
	w.WriteMsg(reply)
}

type MatchType uint8

const (
	prefix MatchType = iota
	suffix
	contain
	fqdn
	other
)

type RuleSimple struct {
	rule   string
	method MatchType
	dns.Handler
}

func (p *RuleSimple) Match(address string) bool {
	switch p.method {
	case prefix:
		return strings.HasPrefix(address, p.rule)
	case suffix:
		return strings.HasSuffix(dns.Fqdn(address), dns.Fqdn(p.rule))
	case contain:
		return strings.Contains(address, p.rule)
	case fqdn:
		return address == dns.Fqdn(p.rule)
	case other:
		return true
	default:
		return false
	}
}
func NewDNS(address, method string) (*DNS, error) {
	if method != "" && method != "tcp" && method != "udp" && method != "tcp-tls" {
		return nil, errors.Errorf("Unregistered query method:%s", method)
	}
	return &DNS{address, &dns.Client{Net: method}}, nil
}

type DNS struct {
	address string
	client  *dns.Client
}

func (s *DNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	reply, _, err := s.client.Exchange(r, s.address)
	if err != nil {
		w.WriteMsg(new(dns.Msg).SetRcode(r, 2))
		logger.Warn(err)
		return
	}
	w.WriteMsg(reply.SetReply(r))
}
func NewRuleGroup(name string, handler dns.Handler) (*RuleGroup, error) {
	list, ok := config.Groups[name]
	if !ok {
		logger.Debugf("%+v", config.Groups)
		return nil, errors.Errorf("Group does not exist:%s", name)
	}
	dict := make(map[string]struct{}, len(list.List))
	for _, domain := range list.List {
		dict[dns.Fqdn(domain)] = struct{}{}
	}
	return &RuleGroup{dict, handler}, nil

}

type Reject struct {
}

func (*Reject) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeRefused))
}

type RuleGroup struct {
	dict map[string]struct{}
	dns.Handler
}

func (r *RuleGroup) Match(address string) bool {
	_, ok := r.dict[address]
	return ok
}
