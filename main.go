package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
)

var version = "debug"

func main() {
	if len(os.Args) < 3 && !(len(os.Args) == 2 && strings.ToUpper(os.Args[1]) == "LIST") {
		fmt.Println("Simple DNS lookup tool (github.com/pschou/dns), version: "+version+
			"\n\nSyntax:", os.Args[0], "TYPE HOST\n"+
			"  TYPE := A, AAAA  - Lookup said record\n"+
			"          PTR  - Reverse lookup ip\n"+
			"  HOST := Source value for lookup, IP or FQDN\n"+
			os.Args[0], "LIST - list all dns servers")
		return
	}

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")

	c := new(dns.Client)
	m := new(dns.Msg)
	m.RecursionDesired = true

	for i := 0; i < len(config.Servers) && (i == 0 || err != nil); i++ {

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
			r, _, err = c.Exchange(m, config.Servers[i]+":"+config.Port)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.A); ok {
						fmt.Printf("%s\n", mx.A.String())
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("lookup error")
				}
			}

		case "AAAA":
			var r *dns.Msg
			m.SetQuestion(strings.TrimSuffix(os.Args[2], ".")+".", dns.TypeAAAA)
			r, _, err = c.Exchange(m, config.Servers[i]+":"+config.Port)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.AAAA); ok {
						fmt.Printf("%s\n", mx.AAAA.String())
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("lookup error")
				}
			}

		case "PTR":
			var r *dns.Msg
			fqdn, _ := dns.ReverseAddr(os.Args[2])
			m.SetQuestion(fqdn, dns.TypePTR)
			r, _, err = c.Exchange(m, config.Servers[i]+":"+config.Port)
			if err == nil {
				for _, a := range r.Answer {
					if mx, ok := a.(*dns.PTR); ok {
						fmt.Printf("%s\n", strings.TrimSuffix(string(mx.Ptr), "."))
					}
				}
				if r.Rcode != dns.RcodeSuccess {
					err = errors.New("lookup error")
				}
			}

			/*
				case "AAAA":
					var hosts []net.IP
					//hosts, err = net.LookupIP(os.Args[2])
					hosts, err = resolver.LookupIP(context.Background(), "ip6", os.Args[2])
					if err == nil {
						for _, h := range hosts {
							if len(h) == 16 {
								fmt.Println(h)
								return
							}
						}
					}

				case "PTR":
					var hosts []string
					//hosts, err = net.LookupAddr(os.Args[2])
					hosts, err = resolver.LookupAddr(context.Background(), os.Args[2])
					if err == nil {
						for _, h := range hosts {
							fmt.Println(strings.TrimSuffix(h, "."))
						}
					}
			*/
		default:
			err = errors.New("unknown option")
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
