# cidranger
Fast IP to belonging CIDR block(s) lookup using trie implementation, e.g. 192.168.0.1 is contained in 192.168.0.0/24

[![GoDoc Reference](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/yl2chen/cidranger)
[![Build Status](https://travis-ci.org/yl2chen/cidranger.svg?branch=master)](https://travis-ci.org/yl2chen/cidranger)

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
BenchmarkLPCTrieHitUsingAWSRanges-4        	   5000000	      256.00 ns/op
BenchmarkBruteRangerHitUsingAWSRanges-4    	    100000	    14739.00 ns/op
BenchmarkLPCTrieMissUsingAWSRanges-4       	  20000000	       57.50 ns/op
BenchmarkBruteRangerMissUsingAWSRanges-4   	     50000	    25038.00 ns/op
```

### TODO
* Implement level-compressed component of LPC trie ranger.
* Add support for IPv6
