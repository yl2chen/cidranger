# cidranger
Fast IP to CIDR block(s) lookup using trie in Golang, inspired by [IPv4 route lookup linux](https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux).

[![GoDoc Reference](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/yl2chen/cidranger)
[![Build Status](https://img.shields.io/travis/yl2chen/cidranger.svg?branch=master&style=flat-square)](https://travis-ci.org/yl2chen/cidranger)
[![Go Report Card](https://goreportcard.com/badge/github.com/yl2chen/cidranger?&style=flat-square)](https://goreportcard.com/report/github.com/yl2chen/cidranger)

Trie storing CIDR blocks `128.0.0.0/2` `192.0.0.0/2` `200.0.0.5` without path compression.
<p align="left"><img src="http://i.imgur.com/vSKTEBb.png" width="600" /></p>

Trie storing same CIDR blocks with path compression, improving both lookup speed and memory footprint.
<p align="left"><img src="http://i.imgur.com/JtaDlD4.png" width="600" /></p>

## Getting Started
Configure imports.
```go
import (
  "net"

  "github.com/yl2chen/cidranger"
)
```
Create a new ranger implemented using Path-Compressed prefix trie.
```go
ranger := NewPCTrieRanger()
```
Inserts CIDR blocks.
```go
_, network1, _ := net.ParseCIDR("192.168.1.0/24")
_, network2, _ := net.ParseCIDR("128.168.1.0/24")
ranger.Insert(*network1)
ranger.Insert(*network2)
```
The prefix trie can be visualized as:
```
0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 128.0.0.0/1 (target_pos:30:has_entry:false)
| | 0--> 128.168.1.0/24 (target_pos:7:has_entry:true)
| | 1--> 192.168.1.0/24 (target_pos:7:has_entry:true)
```
To test if given IP is contained in constructed ranger,
```go
contains, err = ranger.Contains(net.ParseIP("128.168.1.0")) // returns true, nil
contains, err = ranger.Contains(net.ParseIP("192.168.2.0")) // returns false, nil
```
To get all the networks given is contained in,
```go
containingNetworks, err = ranger.ContainingNetworks(net.ParseIP("128.168.1.0"))
```

## Benchmark
Compare hit/miss case for IPv4/IPv6 using PC trie vs brute force implementation, Ranger is initialized with published AWS ip ranges.
```go
// Ipv4 lookup hit scenario
BenchmarkPCTrieHitIPv4UsingAWSRanges-4         	 5000000	       353   ns/op
BenchmarkBruteRangerHitIPv4UsingAWSRanges-4    	  100000	     13719   ns/op

// Ipv6 lookup hit scenario
BenchmarkPCTrieHitIPv6UsingAWSRanges-4         	10000000	       143   ns/op
BenchmarkBruteRangerHitIPv6UsingAWSRanges-4    	  300000	      5178   ns/op

// Ipv4 lookup miss scenario
BenchmarkPCTrieMissIPv4UsingAWSRanges-4        	20000000	        96.5 ns/op
BenchmarkBruteRangerMissIPv4UsingAWSRanges-4   	   50000	     24781   ns/op

// Ipv6 lookup miss scenario
BenchmarkPCTrieHMissIPv6UsingAWSRanges-4       	10000000	       115   ns/op
BenchmarkBruteRangerMissIPv6UsingAWSRanges-4   	  100000	     10824   ns/op
```

## Example of IPv6 trie:
```
::/0 (target_pos:127:has_entry:false)
| 0--> 2400::/14 (target_pos:113:has_entry:false)
| | 0--> 2400:6400::/22 (target_pos:105:has_entry:false)
| | | 0--> 2400:6500::/32 (target_pos:95:has_entry:false)
| | | | 0--> 2400:6500::/39 (target_pos:88:has_entry:false)
| | | | | 0--> 2400:6500:0:7000::/53 (target_pos:74:has_entry:false)
| | | | | | 0--> 2400:6500:0:7000::/54 (target_pos:73:has_entry:false)
| | | | | | | 0--> 2400:6500:0:7000::/55 (target_pos:72:has_entry:false)
| | | | | | | | 0--> 2400:6500:0:7000::/56 (target_pos:71:has_entry:true)
| | | | | | | | 1--> 2400:6500:0:7100::/56 (target_pos:71:has_entry:true)
| | | | | | | 1--> 2400:6500:0:7200::/56 (target_pos:71:has_entry:true)
| | | | | | 1--> 2400:6500:0:7400::/55 (target_pos:72:has_entry:false)
| | | | | | | 0--> 2400:6500:0:7400::/56 (target_pos:71:has_entry:true)
| | | | | | | 1--> 2400:6500:0:7500::/56 (target_pos:71:has_entry:true)
| | | | | 1--> 2400:6500:100:7000::/54 (target_pos:73:has_entry:false)
| | | | | | 0--> 2400:6500:100:7100::/56 (target_pos:71:has_entry:true)
| | | | | | 1--> 2400:6500:100:7200::/56 (target_pos:71:has_entry:true)
| | | | 1--> 2400:6500:ff00::/64 (target_pos:63:has_entry:true)
| | | 1--> 2400:6700:ff00::/64 (target_pos:63:has_entry:true)
| | 1--> 2403:b300:ff00::/64 (target_pos:63:has_entry:true)
```
