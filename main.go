package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
)

var version = "debug"

func main() {
	if len(os.Args) < 3 && !(len(os.Args) == 2 && strings.ToUpper(os.Args[1]) == "LIST") {
		fmt.Println("Simple DNS lookup tool, Written by paul (paulschou.com), Docs: github.com/pschou/dns, Version: "+version+
			"\n\nSyntax:", os.Args[0], "TYPE HOST [SERVER]\n"+
			"  TYPE   := A, AAAA, CNAME, MX, SRV, TXT - Lookup said record\n"+
			"            PTR  - Reverse lookup ip\n"+
			"            LIST - list all dns servers\n"+
			"  HOST   := Source value for lookup, IP or FQDN\n"+
			"  SERVER := Optional, which DNS server to query\n")
		return
	}

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")

	c := new(dns.Client)
	m := new(dns.Msg)
	m.RecursionDesired = true

	for i := 0; i < len(config.Servers) || len(os.Args) > 3 && (i == 0 || err != nil); i++ {
		var server string
		if len(os.Args) > 3 {
			if i < 1 {
				_, _, err = net.SplitHostPort(os.Args[3])
				if err != nil {
					server = net.JoinHostPort(os.Args[3], "53")
				} else {
					server = os.Args[3]
				}
			} else {
				break
			}
		} else {
			server = config.Servers[i] + ":" + config.Port
		}

		switch strings.ToUpper(os.Args[1]) {
		case "LIST":
			if err == nil {
				for _, h := range config.Servers {
					fmt.Println(h)
				}
				return
			}

		case "A":
			var r *dns.Msg
			m.SetQuestion(strings.TrimSuffix(os.Args[2], ".")+".", dns.TypeA)
			r, _, err = c.Exchange(m, server)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.A); ok {
						fmt.Printf("%s\n", mx.A.String())
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("A lookup error " + os.Args[2])
				}
			}

		case "AAAA":
			var r *dns.Msg
			m.SetQuestion(strings.TrimSuffix(os.Args[2], ".")+".", dns.TypeAAAA)
			r, _, err = c.Exchange(m, server)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.AAAA); ok {
						fmt.Printf("%s\n", mx.AAAA.String())
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("AAAA lookup error " + os.Args[2])
				}
			}

		case "PTR":
			var r *dns.Msg
			fqdn, _ := dns.ReverseAddr(os.Args[2])
			m.SetQuestion(fqdn, dns.TypePTR)
			r, _, err = c.Exchange(m, server)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.PTR); ok {
						fmt.Printf("%s\n", strings.TrimSuffix(string(mx.Ptr), "."))
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("PTR lookup error " + os.Args[2])
				}
			}

		case "MX":
			var r *dns.Msg
			m.SetQuestion(strings.TrimSuffix(os.Args[2], ".")+".", dns.TypeMX)
			r, _, err = c.Exchange(m, server)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.MX); ok {
						for _, s := range strings.Split(mx.Mx, "\n") {
							fmt.Printf("%s\n", strings.TrimSuffix(s, "."))
						}
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("MX lookup error " + os.Args[2])
				}
			}

		case "CNAME":
			var r *dns.Msg
			m.SetQuestion(strings.TrimSuffix(os.Args[2], ".")+".", dns.TypeCNAME)
			r, _, err = c.Exchange(m, server)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.CNAME); ok {
						fmt.Printf("%s\n", strings.TrimSuffix(mx.Target, "."))
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("CNAME lookup error " + os.Args[2])
				}
			}

		case "TXT":
			var r *dns.Msg
			m.SetQuestion(strings.TrimSuffix(os.Args[2], ".")+".", dns.TypeTXT)
			r, _, err = c.Exchange(m, server)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.TXT); ok {
						for _, s := range mx.Txt {
							fmt.Printf("%s\n", s)
						}
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("TXT lookup error " + os.Args[2])
				}
			}

		case "SRV":
			var r *dns.Msg
			m.SetQuestion(strings.TrimSuffix(os.Args[2], ".")+".", dns.TypeSRV)
			r, _, err = c.Exchange(m, server)
			if err == nil {
				list := [](*dns.SRV){}
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.SRV); ok {
						list = append(list, mx)
					}
				}
				rand.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
				sort.Sort(byPrioityWeight(list))

				for _, mx := range list {
					fmt.Printf("%s:%d\n", strings.TrimSuffix(mx.Target, "."), mx.Port)
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("SRV lookup error " + os.Args[2])
				}
			}

		default:
			err = errors.New("unknown option")
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type byPrioityWeight [](*dns.SRV)

func (list byPrioityWeight) Len() int {
	return len(list)
}
func (list byPrioityWeight) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}
func (list byPrioityWeight) Less(i, j int) bool {
	if list[i].Priority < list[j].Priority {
		return true
	}
	if list[i].Priority == list[j].Priority {
		return int64(list[i].Weight)*(5+rand.Int63n(20)) > int64(list[j].Weight)*(5+rand.Int63n(20))
	}

	return false
}
