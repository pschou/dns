package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"unsafe"
)

var version = "debug"

func seedRand() {
	buffer := make([]byte, 8)
	file, err := os.Open("/dev/urandom")
	if err != nil {
		if debug {
			fmt.Println("error opening random", err)
		}
		return
	}
	defer file.Close()
	bytesread, err := file.Read(buffer)
	if err != nil || bytesread != 8 {
		if debug {
			fmt.Println("error reading random", err)
		}
		return
	}
	rand.Seed(*(*int64)(unsafe.Pointer(&buffer)))
}

var debug = false

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-debug" {
		debug = true
		os.Args = os.Args[1:]
	}

	if len(os.Args) < 3 && !(len(os.Args) == 2 && (strings.ToUpper(os.Args[1]) == "LIST" || strings.ToUpper(os.Args[1]) == "MYIP")) {
		fmt.Println("Simple DNS lookup tool, Written by paul (paulschou.com), Docs: github.com/pschou/dnsq, Version: "+version+
			"\n\nSyntax:", os.Args[0], "TYPE HOST [SERVER]\n"+
			"  TYPE   := A, AAAA, CNAME, MX, SRV, TXT - Lookup said record\n"+
			"            PTR  - Reverse lookup ip\n"+
			"            LIST - List all dns servers\n"+
			"            MYIP - Try to determine this systems routeable IP.\n"+
			"  HOST   := Source value for lookup, IP or FQDN\n"+
			"  SERVER := Optional, which DNS server to query\n"+
			"For querying the IP address from a custom HTTPS endpoint use:\n"+
			"  WHATISMYIP=ifconfig.me", os.Args[0], "MYIP")
		os.Exit(1)
		return
	}

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")

	c := new(dns.Client)
	m := new(dns.Msg)
	m.RecursionDesired = true

serverLoop:
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
				break serverLoop
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
				break
			}

		case "MYIP":
			ifaces, err := net.Interfaces()
			if err != nil {
				break serverLoop
			}
			var myIPs [](net.IP)
			for _, i := range ifaces {
				addrs, err := i.Addrs()
				if err != nil {
					break serverLoop
				}
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip != nil {
						var private bool
						private, err = isPrivateIP(ip)
						if err != nil {
							break serverLoop
						}
						if !private {
							myIPs = append(myIPs, ip)
						}
					}
					//if
					// process IP address
				}
			}
			if len(myIPs) == 0 {
				lookups := []string{
					"http://checkip.amazonaws.com", "https://checkip.amazonaws.com",
					"http://ifconfig.me", "https://ifconfig.me",
					"http://icanhazip.com", "https://icanhazip.com",
					"http://ipecho.net/plain", "https://ipecho.net/plain",
					"http://ifconfig.co", "https://ifconfig.co",
				}
				whatIsMyIP := os.Getenv("WHATISMYIP")
				if len(whatIsMyIP) > 0 {
					lookups = strings.Split(whatIsMyIP, ",")
				}
				if len(lookups) > 1 {
					seedRand()
					rand.Shuffle(len(lookups), func(i, j int) { lookups[i], lookups[j] = lookups[j], lookups[i] })
				}
				for _, lookup := range lookups {
					if debug {
						fmt.Println(lookup)
					}
					var resp *http.Response
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
					resp, err = http.Get(lookup)
					if err != nil {
						if debug {
							fmt.Println("err", err)
						}
						continue
					}

					if resp.Header.Get("Location") != "" {
						newLoc := resp.Header.Get("Location")
						if debug {
							fmt.Println("found new location", newLoc)
						}
						resp.Body.Close()
						resp, err = http.Get(newLoc)
						if err != nil {
							continue
						}
						defer resp.Body.Close()
					}
					buffer := make([]byte, 128)
					var buflen int
					buflen, err = resp.Body.Read(buffer)
					if buflen == 0 {
						if debug {
							fmt.Println("err", err)
						}
						continue
					}
					IP := net.ParseIP(strings.TrimSpace(string(buffer[:buflen])))
					if IP == nil {
						continue
					}
					err = nil
					fmt.Println(IP.String())
					break serverLoop
				}
				break serverLoop
			}
			for _, ip := range myIPs {
				fmt.Println(ip)
			}
			break

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
						break serverLoop
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
				seedRand()
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

func isPrivateIP(IP net.IP) (bool, error) {
	var err error
	//IP := net.ParseIP(ip)
	if IP == nil {
		err = errors.New("Invalid IP")
	} else {
		for _, cidr := range []string{
			"127.0.0.0/8",    // IPv4 loopback
			"10.0.0.0/8",     // RFC1918
			"172.16.0.0/12",  // RFC1918
			"192.168.0.0/16", // RFC1918
			"169.254.0.0/16", // RFC3927 link-local
			"::1/128",        // IPv6 loopback
			"fe80::/10",      // IPv6 link-local
			"fc00::/7",       // IPv6 unique local addr
		} {
			_, block, err := net.ParseCIDR(cidr)
			if err != nil {
				return false, err
			}
			if block.Contains(IP) {
				return true, nil
			}
		}
	}
	return false, err
}
