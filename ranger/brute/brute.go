/*
Package brute provides the brute force implementation of Ranger.  Insertion and
deletion of networks is performed on an internal storage in the form of
map[string]net.IPNet (constant time operations).  However, inclusion tests are
always performed linearly at no guaranteed traversal order of recorded networks,
so one can assume a worst case performance of O(N).  The performance can be
boosted by changing usage of net.IPNet.Contains() to using masked bits
equality checking, but the main purpose of this implementation is for testing
because the correctness of this implementation can be easily guaranteed, and
used as the ground truth when running a wider range of 'random' tests on other
more sophisticated implementations.
*/
package brute

import (
	"net"

	"github.com/yl2chen/cidranger/ranger"
)

// Ranger is a Ranger that uses brute force operations.
type Ranger struct {
	ipV4Networks map[string]net.IPNet
	ipV6Networks map[string]net.IPNet
}

// NewRanger returns a new Ranger.
func NewRanger() *Ranger {
	return &Ranger{
		ipV4Networks: make(map[string]net.IPNet),
		ipV6Networks: make(map[string]net.IPNet),
	}
}

// Insert inserts a network into ranger.
func (b *Ranger) Insert(network net.IPNet) error {
	key := network.String()
	if _, found := b.ipV4Networks[key]; !found {
		networks, err := b.getNetworksByVersion(network.IP)
		if err != nil {
			return err
		}
		networks[key] = network
	}
	return nil
}

// Remove removes a network from ranger.
func (b *Ranger) Remove(network net.IPNet) (*net.IPNet, error) {
	networks, err := b.getNetworksByVersion(network.IP)
	if err != nil {
		return nil, err
	}
	key := network.String()
	if networkToDelete, found := networks[key]; found {
		delete(networks, key)
		return &networkToDelete, nil
	}
	return nil, nil
}

// Contains returns bool indicating whether given ip is contained by any
// network in ranger.
func (b *Ranger) Contains(ip net.IP) (bool, error) {
	networks, err := b.getNetworksByVersion(ip)
	if err != nil {
		return false, err
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ContainingNetworks returns all networks given ip is a part of.
func (b *Ranger) ContainingNetworks(ip net.IP) ([]net.IPNet, error) {
	networks, err := b.getNetworksByVersion(ip)
	if err != nil {
		return nil, err
	}
	results := []net.IPNet{}
	for _, network := range networks {
		if network.Contains(ip) {
			results = append(results, network)
		}
	}
	return results, nil
}

func (b *Ranger) getNetworksByVersion(ip net.IP) (map[string]net.IPNet, error) {
	if ip.To4() != nil {
		return b.ipV4Networks, nil
	}
	if ip.To16() != nil {
		return b.ipV6Networks, nil
	}
	return nil, ranger.ErrInvalidNetworkInput
}
