package brute

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInsert(t *testing.T) {
	ranger := NewRanger()
	_, network, _ := net.ParseCIDR("0.0.1.0/24")

	ranger.Insert(*network)

	assert.Equal(t, 1, len(ranger.networks))
	assert.Equal(t, *network, ranger.networks["0.0.1.0/24"])
}

func TestRemove(t *testing.T) {
	ranger := NewRanger()
	_, network, _ := net.ParseCIDR("0.0.1.0/24")

	ranger.Insert(*network)
	deleted, err := ranger.Remove(*network)

	assert.NoError(t, err)
	assert.Equal(t, network, deleted)
	assert.Equal(t, 0, len(ranger.networks))
}

func TestContains(t *testing.T) {
	ranger := NewRanger()
	_, network, _ := net.ParseCIDR("0.0.1.0/24")
	ranger.Insert(*network)

	cases := []struct {
		ip       net.IP
		contains bool
		name     string
	}{
		{net.ParseIP("0.0.1.255"), true, "Should contain"},
		{net.ParseIP("0.0.0.255"), false, "Shouldn't contain"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contains, err := ranger.Contains(tc.ip)
			assert.NoError(t, err)
			assert.Equal(t, tc.contains, contains)
		})
	}
}

func TestContainingNetworks(t *testing.T) {
	ranger := NewRanger()
	_, network1, _ := net.ParseCIDR("0.0.1.0/24")
	_, network2, _ := net.ParseCIDR("0.0.1.0/25")
	ranger.Insert(*network1)
	ranger.Insert(*network2)

	cases := []struct {
		ip                 net.IP
		containingNetworks []net.IPNet
		name               string
	}{
		{net.ParseIP("0.0.1.255"), []net.IPNet{*network1}, "Should contain"},
		{net.ParseIP("0.0.1.127"), []net.IPNet{*network1, *network2}, "Should contain both"},
		{net.ParseIP("0.0.0.127"), []net.IPNet{}, "Should contain none"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			networks, err := ranger.ContainingNetworks(tc.ip)
			assert.NoError(t, err)
			assert.Equal(t, len(tc.containingNetworks), len(networks))
			for _, network := range tc.containingNetworks {
				assert.Contains(t, networks, network)
			}
		})
	}
}
