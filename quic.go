package main

import (
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"net/url"
	"sync"
)

var pool = &sync.Pool{New: func() any {
	return [1024]byte{}
}}

func NewQuicDns(address string) (Provider, error) {
	info, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("解析网址失败:%w", err)
	}
	logger.Debugf("quic hostname:%s", info.Hostname())
	s, err := quic.DialAddr(info.Host, &tls.Config{ServerName: info.Hostname()},
		&quic.Config{
			KeepAlive: true,
		},
	)
	if err != nil {
		return nil, err
	}
	return &QuicDns{
		address: address,
		s:       s,
	}, nil
}

type QuicDns struct {
	address string
	s       quic.Session
}

func (q *QuicDns) name() string {
	return q.address
}

func (q *QuicDns) query(msg *dns.Msg) (*dns.Msg, error) {
	data := pool.Get().([]byte)
	defer pool.Put(data)
	payload, err := msg.PackBuffer(data[:])
	if err != nil {
		return nil, err
	}
	stream, err := q.s.OpenStream()
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	_, err = stream.Write(payload)
	if err != nil {
		return nil, err
	}
	n, err := stream.Read(data[:])
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	err = reply.Unpack(data[:n])
	if err != nil {
		return nil, err
	}
	return reply, nil
}
