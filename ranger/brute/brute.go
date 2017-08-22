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

import "net"

// Ranger is a Ranger that uses brute force operations.
type Ranger struct {
	networks map[string]net.IPNet
}

// NewRanger returns a new Ranger.
func NewRanger() *Ranger {
	return &Ranger{
		networks: make(map[string]net.IPNet),
	}
}

// Insert inserts a network into ranger.
func (b *Ranger) Insert(network net.IPNet) error {
	key := network.String()
	if _, found := b.networks[key]; !found {
		b.networks[key] = network
	}
	return nil
}

// Remove removes a network from ranger.
func (b *Ranger) Remove(network net.IPNet) (*net.IPNet, error) {
	key := network.String()
	if networkToDelete, found := b.networks[key]; found {
		delete(b.networks, key)
		return &networkToDelete, nil
	}
	return nil, nil
}

// Contains returns bool indicating whether given ip is contained by any
// network in ranger.
func (b *Ranger) Contains(ip net.IP) (bool, error) {
	for _, network := range b.networks {
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ContainingNetworks returns all networks given ip is a part of.
func (b *Ranger) ContainingNetworks(ip net.IP) ([]net.IPNet, error) {
	networks := []net.IPNet{}
	for _, network := range b.networks {
		if network.Contains(ip) {
			networks = append(networks, network)
		}
	}
	return networks, nil
}
