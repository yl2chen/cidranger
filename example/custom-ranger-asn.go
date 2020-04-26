/*
	Example of how to extend github.com/yl2chen/cidranger

	This adds ASN as a string field, along with methods to get the ASN and the CIDR as strings

	Thank you to yl2chen for his assistance and work on this library
*/
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/yl2chen/cidranger"
)

// custom structure that conforms to RangerEntry interface
type customRangerEntry struct {
	ipNet net.IPNet
	asn   string
}

// get function for network
func (b *customRangerEntry) Network() net.IPNet {
	return b.ipNet
}

// get function for network converted to string
func (b *customRangerEntry) NetworkStr() string {
	return b.ipNet.String()
}

// get function for ASN
func (b *customRangerEntry) Asn() string {
	return b.asn
}

// create customRangerEntry object using net and asn
func newCustomRangerEntry(ipNet net.IPNet, asn string) cidranger.RangerEntry {
	return &customRangerEntry{
		ipNet: ipNet,
		asn:   asn,
	}
}

// entry point
func main() {

	// instantiate NewPCTrieRanger
	ranger := cidranger.NewPCTrieRanger()

	// Load sample data using our custom function
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	ranger.Insert(newCustomRangerEntry(*network, "0001"))

	_, network, _ = net.ParseCIDR("128.168.1.0/24")
	ranger.Insert(newCustomRangerEntry(*network, "0002"))

	// Check if IP is contained within ranger
	contains, err := ranger.Contains(net.ParseIP("128.168.1.7"))
	if err != nil {
		fmt.Println("ranger.Contains()", err.Error())
		os.Exit(1)
	}
	fmt.Println("Contains:", contains)

	// request networks containing this IP
	ip := "192.168.1.42"
	entries, err := ranger.ContainingNetworks(net.ParseIP(ip))
	if err != nil {
		fmt.Println("ranger.ContainingNetworks()", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Entries for %s:\n", ip)
	for _, e := range entries {

		// Cast e (cidranger.RangerEntry to struct customRangerEntry
		entry, ok := e.(*customRangerEntry)
		if !ok {
			continue
		}

		// Get network (converted to string by function)
		n := entry.NetworkStr()

		// Get ASN
		a := entry.Asn()

		// Display
		fmt.Println("\t", n, a)
	}
}
