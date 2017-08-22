/*
Package cidranger provides utility to store CIDR blocks and perform ip
inclusion tests against it.

To create a new instance of the LPC (Level Path Compressed) trie:

			ranger := NewLPCTrieRanger()

To insert or remove cidr blocks (network ranges):
			_, network, _ := net.ParseCIDR("192.168.0.0/24")
			ranger.Insert(network)
			ranger.Remove(network)

To test whether an IP is contained in the constructed networks ranger:

			// returns bool, error
			containsBool, err := ranger.Contains(net.ParseIP("192.168.0.1"))

To get a list of CIDR blocks in constructed ranger that contains IP:

			// returns []net.IPNet, error
			networks, err := ranger.ContainingNetworks(net.ParseIP("192.168.0.1"))

*/
package cidranger

import (
	"net"

	"github.com/yl2chen/cidranger/ranger/brute"
	"github.com/yl2chen/cidranger/ranger/trie"
)

// Ranger is an interface for cidr block containment lookups.
type Ranger interface {
	Insert(network net.IPNet) error
	Remove(network net.IPNet) (*net.IPNet, error)
	Contains(ip net.IP) (bool, error)
	ContainingNetworks(ip net.IP) ([]net.IPNet, error)
}

// NewLPCTrieRanger returns an instance of LPC trie ranger.
func NewLPCTrieRanger() Ranger {
	return trie.NewPrefixTree()
}

// NewBruteRanger returns an instance of brute force ranger.
func NewBruteRanger() Ranger {
	return brute.NewRanger()
}
