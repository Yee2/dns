package main

import (
	"bufio"
	"bytes"
	"github.com/miekg/dns"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
)

func NewIPList(file string, provider Provider) (Filter, error) {
	if !filepath.IsAbs(file) {
		file = filepath.Join(filepath.Dir(config.Path), file)
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	r := &IPList{make([]*net.IPNet, 0), provider}

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
	list     []*net.IPNet
	provider Provider
}

func (that *IPList) Do(request *dns.Msg, query Query) (*dns.Msg, error) {
	reply, err := that.provider.query(request)
	if err != nil {
		return query(request)
	}
	for _, rr := range reply.Answer {
		if that.Contains(rr) {
			logger.Debugf("use provider:%s", that.provider.name())
			return reply, nil
		}
	}
	return query(request)
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
