package main

import (
	"fmt"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/BurntSushi/toml"
	"github.com/alexflint/go-arg"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var (
	logger = &logrus.Logger{
		Out:       os.Stdout,
		Formatter: &logrus.TextFormatter{ForceColors: true},
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

type Filter interface {
	Do(request *dns.Msg, query Query) (*dns.Msg, error)
}
type Query func(*dns.Msg) (*dns.Msg, error)
type Provider interface {
	name() string
	query(*dns.Msg) (*dns.Msg, error)
}

func wrap(h Filter, next Query) Query {
	return func(msg *dns.Msg) (*dns.Msg, error) {
		return h.Do(msg, next)
	}
}

var args struct {
	Config string `arg:"-c" help:"config path"`
	Debug  bool   `arg:"-v" help:"debug mode"`
}

func main() {
	args.Config = "config.toml"
	arg.MustParse(&args)
	if args.Debug {
		logger.Level = logrus.TraceLevel
	} else {
		logger.Level = logrus.InfoLevel
	}
	if err := run(); err != nil {
		logger.Errorf("%s", err)
		os.Exit(-1)
	}
}

type MyRecords struct {
	records []dns.RR // 本地解析
}

func (m *MyRecords) Do(request *dns.Msg, next Query) (*dns.Msg, error) {
	question := request.Question[0]
	for _, record := range m.records {
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
			return msg, nil
		}
	}
	return next(request)
}

type Server struct {
	q Query
}

func (rules *Server) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	if len(request.Question) != 1 {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(request, dns.RcodeRefused))
		return
	}
	logger.Infof("[Q] %s", request.Question[0].String())
	reply, err := rules.q(request)
	if err != nil {
		logger.Warnf("query error:%s", err)
	}
	for _, rr := range reply.Answer {
		logger.Infof("[A] %s", rr)
	}
	_ = w.WriteMsg(reply)
}

func run() error {
	data, err := ioutil.ReadFile(args.Config)
	if err != nil {
		return errors.Wrapf(err, "Failed to read configuration file(%s)", args.Config)
	}

	if err := toml.Unmarshal(data, &config); err != nil {
		return errors.Wrapf(err, "Unable to parse configuration file(%s)", args.Config)
	}
	config.Path, _ = filepath.Abs(args.Config)
	logger.Debugf("%+v", config)
	queryChain := func(msg *dns.Msg) (*dns.Msg, error) {
		return new(dns.Msg).SetRcode(msg, dns.RcodeServerFailure), nil
	}
	providers := make(map[string]Provider)
	reject := &Reject{}
	needs := make(map[string]any)
	for _, r := range config.Rules {
		needs[r.Upstream] = ""
	}
	for _, upstream := range config.Upstreams {
		if needs[upstream.Name] == nil {
			logger.Debugf("ignore upstream:%s", upstream.Name)
			continue
		}
		switch upstream.Method {
		case "doh3-json", "doh-json", "doh3-wireformat", "doh3", "doh-wireformat", "doh":
			p, err := NewDoH(upstream.Address, upstream.Method, upstream.Subnet)
			if err != nil {
				return err
			}
			providers[upstream.Name] = p
		case "quic":
			p, err := NewQuicDns(upstream.Address)
			if err != nil {
				return err
			}
			providers[upstream.Name] = p
		case "udp", "tcp", "tcp-tls":
			p, err := NewDNS(upstream.Address, upstream.Method, upstream.Subnet)
			if err != nil {
				return err
			}
			providers[upstream.Name] = p
		default:
			return errors.Errorf("Unregistered query method:%s", upstream.Method)
		}
	}
	n := len(config.Rules)
	for i := n - 1; i >= 0; i-- {
		rule := config.Rules[i]
		var provider Provider
		var ok bool
		if rule.Action == "reject" {
			provider = reject
		} else {
			provider, ok = providers[rule.Upstream]
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
			filter, err := NewAdBlock(array[1], provider)
			if err != nil {
				return errors.Errorf("Create rule error:%s", err)
			}
			queryChain = wrap(filter, queryChain)

		case "iplist":
			filter, err := NewIPList(array[1], provider)
			if err != nil {
				return errors.Errorf("Create rule error:%s", err)
			}
			queryChain = wrap(filter, queryChain)
		case "prefix":
			queryChain = wrap(&RuleSimple{rule: array[1], method: prefix, provider: provider}, queryChain)
		case "suffix":
			queryChain = wrap(&RuleSimple{rule: array[1], method: suffix, provider: provider}, queryChain)
		case "contain":
			queryChain = wrap(&RuleSimple{rule: array[1], method: contain, provider: provider}, queryChain)
		case "fqdn":
			queryChain = wrap(&RuleSimple{rule: array[1], method: fqdn, provider: provider}, queryChain)
		case "other":
			queryChain = wrap(&RuleSimple{method: other, provider: provider}, queryChain)
		default:
			return errors.Errorf("Unregistered match:%s", rule.Name)
		}
	}

	records := &MyRecords{records: make([]dns.RR, 0)}
	// 加载本地的记录
	for _, r := range config.Records {
		rr, err := r.RR()
		if err != nil {
			return err
		}
		records.records = append(records.records, rr)
	}
	queryChain = wrap(records, queryChain)
	servers := make([]*dns.Server, 0, len(config.Servers))
	upstream := &Server{q: queryChain}
	errorChanel := make(chan error)

	for _, serverInfo := range config.Servers {
		server := &dns.Server{Addr: serverInfo.Address, Net: serverInfo.Type, Handler: upstream}
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
	file     string
	filter   *urlfilter.DNSEngine
	provider Provider
}

func (a *AdBlock) Do(request *dns.Msg, query Query) (*dns.Msg, error) {
	if a.match(request.Question[0]) {
		logger.Debugf("use provider:%s", a.provider.name())
		return a.provider.query(request)
	}
	return query(request)
}

func (a *AdBlock) match(question dns.Question) bool {
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

func NewAdBlock(file string, provider Provider) (Filter, error) {
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
	return &AdBlock{file: o, filter: filteringEngine, provider: provider}, nil
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
	rule     string
	method   MatchType
	provider Provider
}

func (p *RuleSimple) Do(request *dns.Msg, query Query) (*dns.Msg, error) {
	if p.match(request.Question[0]) {
		logger.Debugf("use provider:%s", p.provider.name())
		return p.provider.query(request)
	}
	return query(request)
}

func (p *RuleSimple) match(question dns.Question) bool {
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

type Reject struct {
}

func (_ *Reject) name() string {
	return "reject"
}

func (_ *Reject) query(msg *dns.Msg) (*dns.Msg, error) {
	return new(dns.Msg).SetRcode(msg, dns.RcodeRefused), nil
}
