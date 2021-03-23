# dnsq

Simple Domain Name System Querier (DNSQ) commandline tool intended for ease of
bash scripting in an RPM specfile.

The intended use of this tool, is to allow bash escapes to have the ability to do
DNS queries without extra string parsing.  For example:

`[schou]$ ip=($(dnsq A paulschou.com)); echo "The server's ip is ${ip[0]}."`

## Usage
```
$ ./dnsq Simple DNS lookup tool, Written by paul (paulschou.com), Docs: github.com/pschou/dns

Syntax: ./dnsq TYPE HOST [SERVER]
  TYPE   := A, AAAA, CNAME, MX, SRV, TXT - Lookup said record
            PTR  - Reverse lookup ip
            LIST - list all dns servers
  HOST   := Source value for lookup, IP or FQDN
  SERVER := Optional, which DNS server to query
```

## Examples
```
[schou]$ ./dns A google.com
216.239.38.120
[schou]$ ./dns AAAA google.com
2001:4860:4802:32::78
[schou]$ ./dns PTR 216.239.38.120
google.com
[schou]$ ./dns PTR 2001:4860:4802:32::78
google.com
[schou]$ ./dns list
8.8.8.8
```
