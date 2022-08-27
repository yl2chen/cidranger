/*
Package cidranger provides utility to store CIDR blocks and perform ip
inclusion tests against it.

To create a new instance of the path-compressed trie:

			ranger := NewPCTrieRanger()

To insert or remove an entry (any object that satisfies the RangerEntry
interface):

			_, network, _ := net.ParseCIDR("192.168.0.0/24")
			ranger.Insert(NewBasicRangerEntry(*network))
			ranger.Remove(network)

If you desire for any value to be attached to the entry, simply
create custom struct that satisfies the RangerEntry interface:

			type RangerEntry interface {
				Network() net.IPNet
			}

To test whether an IP is contained in the constructed networks ranger:

			// returns bool, error
			containsBool, err := ranger.Contains(net.ParseIP("192.168.0.1"))

To get a list of CIDR blocks in constructed ranger that contains IP:

			// returns []RangerEntry, error
			entries, err := ranger.ContainingNetworks(net.ParseIP("192.168.0.1"))

To get a list of all IPv4/IPv6 rangers respectively:

			// returns []RangerEntry, error
			entries, err := ranger.CoveredNetworks(*AllIPv4)
			entries, err := ranger.CoveredNetworks(*AllIPv6)

*/
package cidranger

import (
	"fmt"
	"net/netip"
)

// ErrInvalidNetworkInput is returned upon invalid network input.
var ErrInvalidNetworkInput = fmt.Errorf("invalid network input")

// ErrInvalidNetworkNumberInput is returned upon invalid network input.
var ErrInvalidNetworkNumberInput = fmt.Errorf("invalid network number input")

// AllIPv4 is a IPv4 CIDR that contains all networks
var AllIPv4 = parseCIDRUnsafe("0.0.0.0/0")

// AllIPv6 is a IPv6 CIDR that contains all networks
var AllIPv6 = parseCIDRUnsafe("0::0/0")

func parseCIDRUnsafe(s string) netip.Prefix {
	cidr, _ := netip.ParsePrefix(s)
	return cidr
}

// RangerEntry is an interface for insertable entry into a Ranger.
type RangerEntry interface {
	Network() netip.Prefix
}

type basicRangerEntry struct {
	ipNet netip.Prefix
}

func (b *basicRangerEntry) Network() netip.Prefix {
	return b.ipNet
}

// NewBasicRangerEntry returns a basic RangerEntry that only stores the network
// itself.
func NewBasicRangerEntry(ipNet netip.Prefix) RangerEntry {
	return &basicRangerEntry{
		ipNet: ipNet, //.Masked(),
	}
}

// Ranger is an interface for cidr block containment lookups.
type Ranger interface {
	Insert(entry RangerEntry) error
	Remove(network netip.Prefix) (RangerEntry, error)
	Contains(ip netip.Addr) (bool, error)
	ContainingNetworks(ip netip.Addr) ([]RangerEntry, error)
	CoveredNetworks(network netip.Prefix) ([]RangerEntry, error)
	Len() int
}

// NewPCTrieRanger returns a versionedRanger that supports both IPv4 and IPv6
// using the path compressed trie implemention.
func NewPCTrieRanger() Ranger {
	return newVersionedRanger(newPrefixTree)
}
