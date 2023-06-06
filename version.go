package cidranger

import (
	"net"

	rnet "github.com/yl2chen/cidranger/net"
)

type rangerFactory[V any] func(v rnet.IPVersion, value ...V) Ranger[V]

type versionedRanger[V any] struct {
	ipV4Ranger Ranger[V]
	ipV6Ranger Ranger[V]
}

func newVersionedRanger[V any](factory rangerFactory[V], defaultValue V) Ranger[V] {
	return &versionedRanger[V]{
		ipV4Ranger: factory(rnet.IPv4, defaultValue),
		ipV6Ranger: factory(rnet.IPv6, defaultValue),
	}
}

func (v *versionedRanger[V]) Insert(entry RangerEntry, value ...V) error {
	var val V
	if len(value) > 0 {
		val = value[0]
	}
	network := entry.Network()
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return err
	}
	return ranger.Insert(entry, val)
}

func (v *versionedRanger[V]) Remove(network net.IPNet) (RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return nil, err
	}
	return ranger.Remove(network)
}

func (v *versionedRanger[V]) Contains(ip net.IP) (bool, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return false, err
	}
	return ranger.Contains(ip)
}

func (v *versionedRanger[V]) ContainingNetworks(ip net.IP) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return nil, err
	}
	return ranger.ContainingNetworks(ip)
}

func (v *versionedRanger[V]) IterByIncomingNetworks(ip net.IP, fn func(network net.IPNet, value V) error) error {
	ranger, err := v.getRangerForIP(ip)
	if err != nil {
		return err
	}

	return ranger.IterByIncomingNetworks(ip, fn)
}

func (v *versionedRanger[V]) CoveredNetworks(network net.IPNet) ([]RangerEntry, error) {
	ranger, err := v.getRangerForIP(network.IP)
	if err != nil {
		return nil, err
	}
	return ranger.CoveredNetworks(network)
}

// Len returns number of networks in ranger.
func (v *versionedRanger[V]) Len() int {
	return v.ipV4Ranger.Len() + v.ipV6Ranger.Len()
}

func (v *versionedRanger[V]) getRangerForIP(ip net.IP) (Ranger[V], error) {
	if ip.To4() != nil {
		return v.ipV4Ranger, nil
	}
	if ip.To16() != nil {
		return v.ipV6Ranger, nil
	}
	return nil, ErrInvalidNetworkNumberInput
}
