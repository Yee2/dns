package main

import (
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"sync"
	"time"
)

var Msg *dns.Msg

func init() {
	Msg = new(dns.Msg)
	Msg.Id = dns.Id()
	Msg.RecursionDesired = true
	Msg.Question = make([]dns.Question, 1)
	Msg.Question[0] = dns.Question{"google.com.", dns.TypeA, dns.ClassINET}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s IP\n", os.Args[0])
		os.Exit(0)
	}
	wg := &sync.WaitGroup{}
	for _, arg := range os.Args[1:] {
		ip := net.ParseIP(arg)
		if ip == nil {
			fmt.Printf("error ip:%s\n", arg)
			continue
		}
		wg.Add(3)
		go func() {
			fmt.Printf("[UDP]%s:%t\n", ip, TestUDP(ip.String()))
			wg.Done()
		}()
		go func() {
			fmt.Printf("[TLS]%s:%t\n", ip, TestTLS(ip.String()))
			wg.Done()
		}()
		go func() {
			fmt.Printf("[TCP]%s:%t\n", ip, TestTCP(ip.String()))
			wg.Done()
		}()
		wg.Wait()
	}
}

func TestUDP(address string) bool {
	client := &dns.Client{Net: "udp", Timeout: time.Second * 3}
	_, _, err := client.Exchange(Msg, fmt.Sprintf("%s:53",address))
	return err == nil
}
func TestTCP(address string) bool {
	client := &dns.Client{Net: "tcp", Timeout: time.Second * 3}
	_, _, err := client.Exchange(Msg, fmt.Sprintf("%s:53",address))
	return err == nil
}

func TestTLS(address string) bool {
	client := &dns.Client{Net: "tcp-tls", Timeout: time.Second * 3, TLSConfig: &tls.Config{}}
	_, _, err := client.Exchange(Msg, fmt.Sprintf("%s:853",address))
	return err == nil
}
