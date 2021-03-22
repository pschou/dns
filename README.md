# dnsq

Simple Domain Name System Query commandline tool intended for ease of bash scripting in an RPM specfile.

## Usage
```
$ ./dns
Simple DNS lookup tool, written by Paul Schou (github.com/pschou/dns), version: 0.1.20210322.1757

Syntax: ./dns TYPE HOST
  TYPE := A, AAAA  - Lookup said record
          PTR  - Reverse lookup ip
  HOST := Source value for lookup, IP or FQDN
./dns LIST - list all dns servers
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
