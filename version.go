package cidranger

import (
	"net"

	rnet "github.com/yl2chen/cidranger/net"
)

type rangerFactory func(v rnet.IPVersion, headers ...HTTPHeader) Ranger

type versionedRanger struct {
	ipV4Ranger Ranger
	ipV6Ranger Ranger
}

func newVersionedRanger(factory rangerFactory, defaultHeaders ...HTTPHeader) Ranger {
	return &versionedRanger{
		ipV4Ranger: factory(rnet.IPv4, defaultHeaders...),
		ipV6Ranger: factory(rnet.IPv6, defaultHeaders...),
	}
}

func (v *versionedRanger) Insert(entry RangerEntry, headers ...HTTPHeader) error {
	network := entry.Network()
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return err
	}
	return ranger.Insert(entry, headers...)
}

func (v *versionedRanger) Remove(network net.IPNet) (RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return nil, err
	}
	return ranger.Remove(network)
}

func (v *versionedRanger) Contains(ip net.IP) (bool, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return false, err
	}
	return ranger.Contains(ip)
}

func (v *versionedRanger) ContainingNetworks(ip net.IP) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return nil, err
	}
	return ranger.ContainingNetworks(ip)
}

func (v *versionedRanger) IterByIncomingNetworks(ip net.IP, fn func(network net.IPNet, headers []HTTPHeader) error) error {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return err
	}

	return ranger.IterByIncomingNetworks(ip, fn)
}

func (v *versionedRanger) CoveredNetworks(network net.IPNet) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return nil, err
	}
	return ranger.CoveredNetworks(network)
}

// Len returns number of networks in ranger.
func (v *versionedRanger) Len() int {
	return v.ipV4Ranger.Len() + v.ipV6Ranger.Len()
}

func (v *versionedRanger) getRangerForIP(ip net.IP) (Ranger, error) {
	if ip.To4() != nil {
		return v.ipV4Ranger, nil
	}
	if ip.To16() != nil {
		return v.ipV6Ranger, nil
	}
	return nil, ErrInvalidNetworkNumberInput
}
