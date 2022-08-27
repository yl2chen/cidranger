package cidranger

import (
	"net/netip"

	rnet "github.com/yl2chen/cidranger/net"
)

type rangerFactory func(rnet.IPVersion) Ranger

type versionedRanger struct {
	ipV4Ranger Ranger
	ipV6Ranger Ranger
}

func newVersionedRanger(factory rangerFactory) Ranger {
	return &versionedRanger{
		ipV4Ranger: factory(rnet.IPv4),
		ipV6Ranger: factory(rnet.IPv6),
	}
}

func (v *versionedRanger) Insert(entry RangerEntry) error {
	network := entry.Network()
	ranger, err := v.getRangerForIP(network.Addr())
	if err != nil {
		return err
	}
	return ranger.Insert(entry)
}

func (v *versionedRanger) Remove(network netip.Prefix) (RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.Addr())
	if err != nil {
		return nil, err
	}
	return ranger.Remove(network)
}

func (v *versionedRanger) Contains(ip netip.Addr) (bool, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return false, err
	}
	return ranger.Contains(ip)
}

func (v *versionedRanger) ContainingNetworks(ip netip.Addr) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return nil, err
	}
	return ranger.ContainingNetworks(ip)
}

func (v *versionedRanger) CoveredNetworks(network netip.Prefix) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.Addr())
	if err != nil {
		return nil, err
	}
	return ranger.CoveredNetworks(network)
}

// Len returns number of networks in ranger.
func (v *versionedRanger) Len() int {
	return v.ipV4Ranger.Len() + v.ipV6Ranger.Len()
}

func (v *versionedRanger) getRangerForIP(ip netip.Addr) (Ranger, error) {
	if ip.Is4() {
		return v.ipV4Ranger, nil
	} else if ip.Is6() {
		return v.ipV6Ranger, nil
	}
	return nil, ErrInvalidNetworkNumberInput
}
