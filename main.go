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

func NewBruteRanger() Ranger {
	return brute.NewRanger()
}
