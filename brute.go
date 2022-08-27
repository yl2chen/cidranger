package cidranger

import (
	"net/netip"

	rnet "github.com/yl2chen/cidranger/net"
)

// bruteRanger is a brute force implementation of Ranger.  Insertion and
// deletion of networks is performed on an internal storage in the form of
// map[string]net.IPNet (constant time operations).  However, inclusion tests are
// always performed linearly at no guaranteed traversal order of recorded networks,
// so one can assume a worst case performance of O(N).  The performance can be
// boosted many ways, e.g. changing usage of net.IPNet.Contains() to using masked
// bits equality checking, but the main purpose of this implementation is for
// testing because the correctness of this implementation can be easily guaranteed,
// and used as the ground truth when running a wider range of 'random' tests on
// other more sophisticated implementations.
type bruteRanger struct {
	ipV4Entries map[netip.Prefix]RangerEntry
	ipV6Entries map[netip.Prefix]RangerEntry
}

// newBruteRanger returns a new Ranger.
func newBruteRanger() Ranger {
	return &bruteRanger{
		ipV4Entries: make(map[netip.Prefix]RangerEntry),
		ipV6Entries: make(map[netip.Prefix]RangerEntry),
	}
}

// Insert inserts a RangerEntry into ranger.
func (b *bruteRanger) Insert(entry RangerEntry) error {
	network := entry.Network()
	key := network
	if _, found := b.ipV4Entries[key]; !found {
		entries, err := b.getEntriesByVersion(entry.Network().Addr())
		if err != nil {
			return err
		}
		entries[key] = entry
	}
	return nil
}

// Remove removes a RangerEntry identified by given network from ranger.
func (b *bruteRanger) Remove(network netip.Prefix) (RangerEntry, error) {
	networks, err := b.getEntriesByVersion(network.Addr())
	if err != nil {
		return nil, err
	}
	key := network
	if networkToDelete, found := networks[key]; found {
		delete(networks, key)
		return networkToDelete, nil
	}
	return nil, nil
}

// Contains returns bool indicating whether given ip is contained by any
// network in ranger.
func (b *bruteRanger) Contains(ip netip.Addr) (bool, error) {
	entries, err := b.getEntriesByVersion(ip)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		network := entry.Network()
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ContainingNetworks returns all RangerEntry(s) that given ip contained in.
func (b *bruteRanger) ContainingNetworks(ip netip.Addr) ([]RangerEntry, error) {
	entries, err := b.getEntriesByVersion(ip)
	if err != nil {
		return nil, err
	}
	results := []RangerEntry{}
	for _, entry := range entries {
		network := entry.Network()
		if network.Contains(ip) {
			results = append(results, entry)
		}
	}
	return results, nil
}

// CoveredNetworks returns the list of RangerEntry(s) the given ipnet
// covers.  That is, the networks that are completely subsumed by the
// specified network.
func (b *bruteRanger) CoveredNetworks(network netip.Prefix) ([]RangerEntry, error) {
	entries, err := b.getEntriesByVersion(network.Addr())
	if err != nil {
		return nil, err
	}
	var results []RangerEntry
	testNetwork := rnet.NewNetwork(network)
	for _, entry := range entries {
		entryNetwork := rnet.NewNetwork(entry.Network())
		if testNetwork.Covers(entryNetwork) {
			results = append(results, entry)
		}
	}
	return results, nil
}

// Len returns number of networks in ranger.
func (b *bruteRanger) Len() int {
	return len(b.ipV4Entries) + len(b.ipV6Entries)
}

func (b *bruteRanger) getEntriesByVersion(ip netip.Addr) (map[netip.Prefix]RangerEntry, error) {
	if ip.Is4() {
		return b.ipV4Entries, nil
	}
	if ip.Is6() {
		return b.ipV6Entries, nil
	}
	return nil, ErrInvalidNetworkInput
}
