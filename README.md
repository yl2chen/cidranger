# cidranger
Fast IP to belonging CIDR block(s) lookup using trie implementation, e.g. 192.168.0.1 is contained in 192.168.0.0/24

[![GoDoc Reference](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/yl2chen/cidranger)
[![Build Status](https://img.shields.io/travis/yl2chen/cidranger.svg?branch=master&style=flat-square)](https://travis-ci.org/yl2chen/cidranger)
[![Go Report Card](https://goreportcard.com/badge/github.com/yl2chen/cidranger?&style=flat-square)](https://goreportcard.com/report/github.com/yl2chen/cidranger)

### Usage
Configure imports.
```
import (
  "net",
  
  "github.com/yl2chen/cidranger"
)
```
Creates a new ranger inmplemented using Level-Path-Compressed (path compressed capability coming soon) trie.
```
ranger := NewLPCTrieRanger()
```
Inserts CIDR blocks.
```
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
To test if given IP is contained in constructed ranger, IPv6 is not currently supported, an error will be returend if called with an IPv6 ip.
```
contains, err = ranger.Contains(net.ParseIP("128.168.1.0")) // returns true, nil
contains, err = ranger.Contains(net.ParseIP("192.168.2.0")) // returns false, nil
```
To get all the networks given is contained in,
```
containingNetworks, err = ranger.ContainingNetworks(net.ParseIP("128.168.1.0"))
```

### Benchmark results comparing hit/miss for LPC trie vs brute force implementation, using AWS published ip ranges.
```
BenchmarkLPCTrieHitIPv4UsingAWSRanges-4        	 3000000	       389 ns/op
BenchmarkLPCTrieHitIPv6UsingAWSRanges-4        	10000000	       149 ns/op
BenchmarkBruteRangerHitIPv4UsingAWSRanges-4    	  100000	     14879 ns/op
BenchmarkBruteRangerHitIPv6UsingAWSRanges-4    	  300000	      3339 ns/op
BenchmarkLPCTrieMissIPv4UsingAWSRanges-4       	20000000	       100 ns/op
BenchmarkLPCTrieHMissIPv6UsingAWSRanges-4      	10000000	       120 ns/op
BenchmarkBruteRangerMissIPv4UsingAWSRanges-4   	   50000	     25367 ns/op
BenchmarkBruteRangerMissIPv6UsingAWSRanges-4   	  100000	     11146 ns/op
```

### Example of IPv6 trie:
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

### TODO
* Implement level-compressed component of LPC trie ranger
