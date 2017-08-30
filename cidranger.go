/*
Package cidranger provides utility to store CIDR blocks and perform ip
inclusion tests against it.

To create a new instance of the path-compressed trie:

			ranger := NewPCTrieRanger()

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
	"fmt"
	"net"
)

// ErrInvalidNetworkInput is returned upon invalid network input.
var ErrInvalidNetworkInput = fmt.Errorf("Invalid network input")

// ErrInvalidNetworkNumberInput is returned upon invalid network input.
var ErrInvalidNetworkNumberInput = fmt.Errorf("Invalid network number input")

// Ranger is an interface for cidr block containment lookups.
type Ranger interface {
	Insert(network net.IPNet) error
	Remove(network net.IPNet) (*net.IPNet, error)
	Contains(ip net.IP) (bool, error)
	ContainingNetworks(ip net.IP) ([]net.IPNet, error)
}

// NewPCTrieRanger returns a versionedRanger that supports both IPv4 and IPv6
// using the path compressed trie implemention.
func NewPCTrieRanger() Ranger {
	return newVersionedRanger(newPrefixTree)
}
