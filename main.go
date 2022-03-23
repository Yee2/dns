package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/BurntSushi/toml"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	logger = &logrus.Logger{
		Out:       os.Stdout,
		Formatter: &logrus.TextFormatter{ForceColors: true},
		Level:     logrus.DebugLevel,
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
	Name() string
	Match(q dns.Question) bool
	Handler
}

func main() {
	rand.Seed(time.Now().UnixNano())

	app := &cli.App{Name: "DNS", Action: run, Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "config.toml",
			Usage: "set the config.toml file path",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "",
		},
	}}
	err := app.Run(os.Args)
	if err != nil {
		logger.Error(err)
		os.Exit(-1)
	}
}

type Rules struct {
	list    []Rule
	records []dns.RR // 本地解析
}

func (rules *Rules) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	// 单个 DNS 请求里面附带多个问题没有任何意义，直接拒绝
	if len(request.Question) != 1 {
		logger.Infof("bad request:%s", request)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(request, 0x05))
		return
	}

	logger.Debugf("query:%s", request.Question[0].String())
	if reply, ok := rules.local(request); ok {
		_ = w.WriteMsg(reply)
		return
	}
	// 作为权威服务器，不进行后续递归查询
	if config.Authoritative {
		reply := new(dns.Msg).SetRcode(request, dns.RcodeNameError)
		reply.RecursionAvailable = false
		reply.Authoritative = true
		_ = w.WriteMsg(reply)
	}
	if reply, ok := rules.resolve(request); ok {
		_ = w.WriteMsg(reply)
	} else {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(request, dns.RcodeNotImplemented))
	}
}
func (rules *Rules) local(request *dns.Msg) (msg *dns.Msg, ok bool) {
	question := request.Question[0]
	for _, record := range rules.records {
		if question.Qclass != dns.ClassANY && question.Qclass != record.Header().Class {
			continue
		}
		if record.Header().Rrtype != question.Qtype {
			continue
		}
		if Compare(record.Header().Name, question.Name) {
			msg := new(dns.Msg).SetReply(request)
			msg.Authoritative = true
			answer := dns.Copy(record)
			answer.Header().Name = question.Name // 泛解析的域名需要转换成具体的域名
			msg.Answer = []dns.RR{answer}
			return msg, true
		}
	}
	return nil, false
}
func (rules *Rules) resolve(request *dns.Msg) (result *dns.Msg, ok bool) {
	q := request.Question[0]
	for _, item := range rules.list {
		if !item.Match(q) {
			continue
		}
		logger.Debugf("try %s", item.Name())
		if reply, err := item.Exchange(request); err != nil {
			logger.Debugf("exchange error:%s", err)
			continue
		} else if len(reply.Answer) > 0 {
			logger.Debugf("usage %s", item.Name())
			return reply, true
		}
	}
	return nil, false
}

type Handler interface {
	Exchange(m *dns.Msg) (r *dns.Msg, err error)
}

func run(ctx *cli.Context) error {
	if ctx.Bool("debug") {
		logger.Level = logrus.TraceLevel
	} else {
		logger.Level = logrus.InfoLevel
	}
	data, err := ioutil.ReadFile(ctx.String("config"))
	if err != nil {
		return errors.Wrapf(err, "Failed to read configuration file(%s)", ctx.String("config"))
	}

	if err := toml.Unmarshal(data, &config); err != nil {
		return errors.Wrapf(err, "Unable to parse configuration file(%s)", ctx.String("config"))
	}
	config.Path, _ = filepath.Abs(ctx.String("config"))
	logger.Debugf("%+v", config)
	handles := make(map[string]Handler)
	reject := &Reject{}
	for _, upstream := range config.Upstreams {

		switch upstream.Method {
		case "doh3-json", "doh-json", "doh3-wireformat", "doh3", "doh-wireformat", "doh":
			handle, err := NewDoH(upstream.Address, upstream.Method, upstream.Subnet)
			if err != nil {
				return err
			}
			handles[upstream.Name] = handle
		case "udp", "tcp", "tcp-tls":
			handle, err := NewDNS(upstream.Address, upstream.Method, upstream.Subnet)
			if err != nil {
				return err
			}
			handles[upstream.Name] = handle
		default:
			return errors.Errorf("Unregistered query method:%s", upstream.Method)
		}
	}
	rules := &Rules{list: make([]Rule, 0), records: make([]dns.RR, 0)}
	// 加载本地的记录
	for _, r := range config.Records {
		rr, err := r.RR()
		if err != nil {
			return err
		}
		rules.records = append(rules.records, rr)
	}
	for _, rule := range config.Rules {
		var handler Handler
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
		case "adblock":
			rule, err := NewAdBlock(array[1], handler)
			if err != nil {
				return errors.Errorf("Create rule error:%s", err)
			}
			rules.list = append(rules.list, rule)
		case "iplist":
			rule, err := NewIPList(array[1], handler)
			if err != nil {
				return errors.Errorf("Create rule error:%s", err)
			}
			rules.list = append(rules.list, rule)
		case "prefix":
			rules.list = append(rules.list, &RuleSimple{rule: array[1], method: prefix, Handler: handler})
		case "suffix":
			rules.list = append(rules.list, &RuleSimple{rule: array[1], method: suffix, Handler: handler})
		case "contain":
			rules.list = append(rules.list, &RuleSimple{rule: array[1], method: contain, Handler: handler})
		case "fqdn":
			rules.list = append(rules.list, &RuleSimple{rule: array[1], method: fqdn, Handler: handler})
		case "other":
			rules.list = append(rules.list, &RuleSimple{method: other, Handler: handler})
		case "group":
			rule, err := NewRuleGroup(array[1], handler)
			if err != nil {
				return err
			}
			rules.list = append(rules.list, rule)
		default:
			return errors.Errorf("Unregistered match:%s", rule.Name)
		}
	}
	for _, r := range rules.list {
		logger.Infof("rule:%s", r.Name())
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

type AdBlock struct {
	file   string
	filter *urlfilter.DNSEngine
	Handler
}

func (a *AdBlock) Name() string {
	return "adBlock - " + a.file
}

func (a *AdBlock) Match(question dns.Question) bool {
	res, ok := a.filter.Match(strings.TrimSuffix(question.Name, "."))
	if !ok {
		return false
	}
	if res.NetworkRule != nil {
		return !res.NetworkRule.Whitelist
	} else if res.HostRulesV4 != nil {
		return true
	} else if res.HostRulesV6 != nil {
		return true
	}
	return false
}

func NewAdBlock(file string, handle Handler) (*AdBlock, error) {
	o := file
	if !filepath.IsAbs(file) {
		file = filepath.Join(filepath.Dir(config.Path), file)
	}
	fileRuleList, err := filterlist.NewFileRuleList(0, file, true)
	if err != nil {
		return nil, fmt.Errorf("filterlist.NewFileRuleList(): %s: %w", file, err)
	}
	defer fileRuleList.Close()
	scanner := fileRuleList.NewScanner()
	var rules []filterlist.RuleList
	for scanner.Scan() {
		r, id := scanner.Rule()
		rules = append(rules, &filterlist.StringRuleList{
			ID:        id,
			RulesText: r.Text(),
		})
	}
	rulesStorage, err := filterlist.NewRuleStorage(rules)
	if err != nil {
		return nil, fmt.Errorf("filterlist.NewRuleStorage(): %w", err)
	}
	filteringEngine := urlfilter.NewDNSEngine(rulesStorage)
	return &AdBlock{file: o, filter: filteringEngine, Handler: handle}, nil
}
func NewIPList(file string, handle Handler) (*IPList, error) {
	if !filepath.IsAbs(file) {
		file = filepath.Join(filepath.Dir(config.Path), file)
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	r := &IPList{make([]*net.IPNet, 0), handle}
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		_, IP, err := net.ParseCIDR(string(line))
		if err != nil {
			logger.Infof("parser IP error:%s", err)
			continue
		}
		r.list = append(r.list, &net.IPNet{
			IP:   IP.IP.Mask(IP.Mask).To16(),
			Mask: IP.Mask,
		})
	}
	sort.Sort(r)
	return r, nil
}

type IPList struct {
	list []*net.IPNet
	Handler
}

func (that *IPList) Name() string {
	return "ipList"
}

func (that *IPList) Len() int {
	return len(that.list)
}

func (that *IPList) Less(i, j int) bool {
	return bytes.Compare(that.list[i].IP, that.list[j].IP) < 0
}

func (that *IPList) Swap(i, j int) {
	that.list[i], that.list[j] = that.list[j], that.list[i]
}

func (that *IPList) Match(question dns.Question) bool {
	return question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA
}

func (that *IPList) Contains(rr dns.RR) bool {
	var ip net.IP
	switch v := rr.(type) {
	case *dns.A:
		ip = v.A.To16()
	case *dns.AAAA:
		ip = v.AAAA
	default:
		return false
	}

	list := that.list
	if len(list) == 0 {
		return false
	}
	for {
		key := len(list) / 2
		if list[key].Contains(ip) {
			return true
		}

		if bytes.Compare(ip, list[key].IP) > 0 {
			list = list[key+1:]
		} else {
			list = list[:key]
		}
		if len(list) == 0 {
			return false
		}
	}
}

func (that *IPList) Exchange(msg *dns.Msg) (r *dns.Msg, err error) {
	reply, err := that.Handler.Exchange(msg)
	if err != nil {
		return nil, err
	}
	for _, rr := range reply.Answer {
		if !that.Contains(rr) {
			return nil, fmt.Errorf("next")
		}
	}
	return reply, nil
}

func NewDoH(address string, method string, subnet string) (*DoH, error) {
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

func (that *DoH) Exchange(m *dns.Msg) (r *dns.Msg, err error) {
	if that.method == 0 {
		return that.json(m)
	} else {
		return that.wireformat(m)
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

type MatchType uint8

const (
	prefix MatchType = iota
	suffix
	ip
	contain
	fqdn
	other
)

type RuleSimple struct {
	rule   string
	method MatchType
	Handler
}

func (p *RuleSimple) Name() string {
	switch p.method {
	case contain:
		return fmt.Sprintf("RuleSimple - contain")
	case fqdn:
		return fmt.Sprintf("RuleSimple - FQDN")
	case ip:
		return fmt.Sprintf("RuleSimple - IP")
	case other:
		return fmt.Sprintf("RuleSimple - other")
	case suffix:
		return fmt.Sprintf("RuleSimple - suffix")
	case prefix:
		return fmt.Sprintf("RuleSimple - prefix")
	}
	return fmt.Sprintf("RuleSimple")
}

func (p *RuleSimple) Match(question dns.Question) bool {
	address := question.Name
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
func NewDNS(address, method string, subnet string) (*DNS, error) {
	_, port, err := net.SplitHostPort(address)
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

func (s *DNS) Exchange(msg *dns.Msg) (reply *dns.Msg, err error) {
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

func NewRuleGroup(name string, handler Handler) (*RuleGroup, error) {
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

func (r2 *Reject) Exchange(m *dns.Msg) (r *dns.Msg, err error) {
	return new(dns.Msg).SetRcode(r, dns.RcodeRefused), nil
}

type RuleGroup struct {
	dict map[string]struct{}
	Handler
}

func (g *RuleGroup) Name() string {
	return "ruleGroup"
}

func (g *RuleGroup) Match(question dns.Question) bool {
	_, ok := g.dict[question.Name]
	return ok
}
