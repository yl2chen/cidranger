package cidranger

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInsert(t *testing.T) {
	ranger := newBruteRanger().(*bruteRanger)
	_, networkIPv4, _ := net.ParseCIDR("0.0.1.0/24")
	_, networkIPv6, _ := net.ParseCIDR("8000::/96")

	ranger.Insert(*networkIPv4)
	ranger.Insert(*networkIPv6)

	assert.Equal(t, 1, len(ranger.ipV4Networks))
	assert.Equal(t, *networkIPv4, ranger.ipV4Networks["0.0.1.0/24"])
	assert.Equal(t, 1, len(ranger.ipV6Networks))
	assert.Equal(t, *networkIPv6, ranger.ipV6Networks["8000::/96"])
}

func TestInsertError(t *testing.T) {
	bRanger := newBruteRanger().(*bruteRanger)
	_, networkIPv4, _ := net.ParseCIDR("0.0.1.0/24")
	networkIPv4.IP = append(networkIPv4.IP, byte(4))
	err := bRanger.Insert(*networkIPv4)
	assert.Equal(t, ErrInvalidNetworkInput, err)
}

func TestRemove(t *testing.T) {
	ranger := newBruteRanger().(*bruteRanger)
	_, networkIPv4, _ := net.ParseCIDR("0.0.1.0/24")
	_, networkIPv6, _ := net.ParseCIDR("8000::/96")
	_, notInserted, _ := net.ParseCIDR("8000::/96")

	ranger.Insert(*networkIPv4)
	deletedIPv4, err := ranger.Remove(*networkIPv4)
	assert.NoError(t, err)

	ranger.Insert(*networkIPv6)
	deletedIPv6, err := ranger.Remove(*networkIPv6)
	assert.NoError(t, err)

	network, err := ranger.Remove(*notInserted)
	assert.NoError(t, err)
	assert.Nil(t, network)

	assert.Equal(t, networkIPv4, deletedIPv4)
	assert.Equal(t, 0, len(ranger.ipV4Networks))
	assert.Equal(t, networkIPv6, deletedIPv6)
	assert.Equal(t, 0, len(ranger.ipV6Networks))
}

func TestRemoveError(t *testing.T) {
	r := newBruteRanger().(*bruteRanger)
	_, invalidNetwork, _ := net.ParseCIDR("0.0.1.0/24")
	invalidNetwork.IP = append(invalidNetwork.IP, byte(4))

	_, err := r.Remove(*invalidNetwork)
	assert.Equal(t, ErrInvalidNetworkInput, err)
}

func TestContains(t *testing.T) {
	r := newBruteRanger().(*bruteRanger)
	_, network, _ := net.ParseCIDR("0.0.1.0/24")
	_, network1, _ := net.ParseCIDR("8000::/112")
	r.Insert(*network)
	r.Insert(*network1)

	cases := []struct {
		ip       net.IP
		contains bool
		err      error
		name     string
	}{
		{net.ParseIP("0.0.1.255"), true, nil, "IPv4 should contain"},
		{net.ParseIP("0.0.0.255"), false, nil, "IPv4 houldn't contain"},
		{net.ParseIP("8000::ffff"), true, nil, "IPv6 shouldn't contain"},
		{net.ParseIP("8000::1:ffff"), false, nil, "IPv6 shouldn't contain"},
		{append(net.ParseIP("8000::1:ffff"), byte(0)), false, ErrInvalidNetworkInput, "Invalid IP"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contains, err := r.Contains(tc.ip)
			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.contains, contains)
			}
		})
	}
}

func TestContainingNetworks(t *testing.T) {
	r := newBruteRanger().(*bruteRanger)
	_, network1, _ := net.ParseCIDR("0.0.1.0/24")
	_, network2, _ := net.ParseCIDR("0.0.1.0/25")
	_, network3, _ := net.ParseCIDR("8000::/112")
	_, network4, _ := net.ParseCIDR("8000::/113")
	r.Insert(*network1)
	r.Insert(*network2)
	r.Insert(*network3)
	r.Insert(*network4)
	cases := []struct {
		ip                 net.IP
		containingNetworks []net.IPNet
		err                error
		name               string
	}{
		{net.ParseIP("0.0.1.255"), []net.IPNet{*network1}, nil, "IPv4 should contain"},
		{net.ParseIP("0.0.1.127"), []net.IPNet{*network1, *network2}, nil, "IPv4 should contain both"},
		{net.ParseIP("0.0.0.127"), []net.IPNet{}, nil, "IPv4 should contain none"},
		{net.ParseIP("8000::ffff"), []net.IPNet{*network3}, nil, "IPv6 should constain"},
		{net.ParseIP("8000::7fff"), []net.IPNet{*network3, *network4}, nil, "IPv6 should contain both"},
		{net.ParseIP("8000::1:7fff"), []net.IPNet{}, nil, "IPv6 should contain none"},
		{append(net.ParseIP("8000::1:7fff"), byte(0)), nil, ErrInvalidNetworkInput, "Invalid IP"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			networks, err := r.ContainingNetworks(tc.ip)
			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tc.containingNetworks), len(networks))
				for _, network := range tc.containingNetworks {
					assert.Contains(t, networks, network)
				}
			}
		})
	}
}
