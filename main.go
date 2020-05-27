package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/BurntSushi/toml"
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
	if len(request.Question) == 0 {
		//TODO: 记录错误信息
		_ = w.WriteMsg(new(dns.Msg).SetRcodeFormatError(request))
		return
	}
	reply := request.Copy()
	opt := request.IsEdns0()
	for _, question := range request.Question {
		// 第一步 查找 config.Records
		logger.Debugf("query:%s", question.String())
		if msg, ok := rules.local(question); ok {
			reply.Answer = append(reply.Answer, msg.Answer...)
			continue
		}
		// 第二步 从外部查询记录
		if result, ok := rules.resolve(question, opt); ok {
			reply.Answer = append(reply.Answer, result.Answer...)
			reply.Ns = append(reply.Ns, result.Ns...)
			reply.Extra = append(reply.Extra, result.Extra...)
			continue
		}
	}
	reply.SetReply(request)
	w.WriteMsg(reply)
}
func (rules *Rules) local(question dns.Question) (msg *dns.Msg, ok bool) {
	for _, record := range rules.records {
		if question.Qclass != dns.ClassANY && question.Qclass != record.Header().Class {
			continue
		}
		if record.Header().Rrtype != question.Qtype {
			continue
		}
		if Compare(record.Header().Name, question.Name) {
			msg := new(dns.Msg)
			msg.Answer = []dns.RR{record}
			return msg, true
		}
	}
	return nil, false
}
func (rules *Rules) resolve(question dns.Question, opt *dns.OPT) (result *dns.Msg, ok bool) {
	msg := new(dns.Msg)
	msg.Question = []dns.Question{question}
	msg.RecursionDesired = true
	if opt != nil {
		msg.Extra = []dns.RR{opt}
	}

	for _, item := range rules.list {
		if !item.Match(question) {
			continue
		}
		logger.Debugf("try %s", item.Name())
		msg.MsgHdr.Id = uint16(rand.Int())
		if reply, err := item.Exchange(msg); err != nil {
			logger.Debugf("exchange error:%s", err)
			continue
		} else if len(reply.Answer) > 0 {
			// FIXME: DNS服务器可能会返回上级NS服务器
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

// TODO: 实现 `HostRule`
func (a *AdBlock) Match(question dns.Question) bool {
	_, ok := a.filter.Match(strings.TrimSuffix(question.Name, "."))
	return ok
}

// TODO: 解除文件占用
func NewAdBlock(file string, handle Handler) (*AdBlock, error) {
	o := file
	if !filepath.IsAbs(file) {
		file = filepath.Join(filepath.Dir(config.Path), file)
	}
	list, err := filterlist.NewFileRuleList(0, file, true)
	if err != nil {
		return nil, fmt.Errorf("filterlist.NewFileRuleList(): %s: %s", file, err)
	}
	rulesStorage, err := filterlist.NewRuleStorage([]filterlist.RuleList{list})
	if err != nil {
		return nil, fmt.Errorf("filterlist.NewRuleStorage(): %s", err)
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
		_, ipnet, err := net.ParseCIDR(string(line))
		if err != nil {
			fmt.Printf("解析IP出现错误:%s\n", err)
			continue
		}
		r.list = append(r.list, ipnet)
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
	return binary.BigEndian.Uint32(that.list[i].IP) < binary.BigEndian.Uint32(that.list[j].IP)
}

func (that *IPList) Swap(i, j int) {
	that.list[i], that.list[j] = that.list[j], that.list[i]
}

func (that *IPList) Match(question dns.Question) bool {
	return question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA
}

func (that *IPList) Contains(ip dns.RR) bool {
	//TODO: 添加对 IPv6 的支持
	if _, ok := ip.(*dns.CNAME); ok {
		return true
	}
	record, ok := ip.(*dns.A)
	if !ok {
		return false
	}
	list := that.list
	if len(list) == 0 {
		return false
	}
	for {
		key := len(list) / 2
		if list[key].Contains(record.A) {
			return true
		}
		if binary.BigEndian.Uint32(record.A.Mask(list[key].Mask)) > binary.BigEndian.Uint32(list[key].IP) {
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

func (that *DoH) Exchange(m *dns.Msg) (r *dns.Msg, err error) {
	if that.method == 0 {
		return that.json(m)
	} else {
		return that.wireformat(m)
	}
}

func (that *DoH) wireformat(r *dns.Msg) (response *dns.Msg, err error) {
	raw, err := r.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns query:%w", err)
	}
	request, err := http.NewRequest("POST", that.address, bytes.NewBuffer(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/dns-udpwireformat")
	request.Header.Add("accept", "application/dns-message")
	resp, err := that.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("dns-over-https:%w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("dns-over-https error code %d", resp.StatusCode)
	}
	defer resp.Body.Close()
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
	// TODO: 修正
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
				logger.Warn(errors.Wrapf(err, "dns-over-https error Answer:%s",
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
func NewDNS(address, method string) (*DNS, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing address error:%w", err)
	}
	if port == "" {
		address = net.JoinHostPort(address, "53")
	}
	if method != "" && method != "tcp" && method != "udp" && method != "tcp-tls" {
		return nil, errors.Errorf("Unregistered query method:%s", method)
	}
	return &DNS{address, &dns.Client{Net: method}}, nil
}

type DNS struct {
	address string
	client  *dns.Client
}

func (s *DNS) Exchange(msg *dns.Msg) (reply *dns.Msg, err error) {
	reply, _, err = s.client.Exchange(msg, s.address)
	logger.Debugf("%s", reply)
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
