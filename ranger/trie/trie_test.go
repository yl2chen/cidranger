package trie

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	rnet "github.com/yl2chen/cidranger/net"
)

func TestInsert(t *testing.T) {
	cases := []struct {
		inserts                      []string
		expectedNetworksInDepthOrder []string
		name                         string
	}{
		{[]string{"192.168.0.1/24"}, []string{"192.168.0.1/24"}, "basic insert"},
		{
			[]string{"192.168.0.1/16", "192.168.0.1/24"},
			[]string{"192.168.0.1/16", "192.168.0.1/24"},
			"in order insert",
		},
		{
			[]string{"192.168.0.1/24", "192.168.0.1/16"},
			[]string{"192.168.0.1/16", "192.168.0.1/24"},
			"reverse insert",
		},
		{
			[]string{"192.168.0.1/24", "192.168.1.1/24"},
			[]string{"192.168.0.1/24", "192.168.1.1/24"},
			"branch insert",
		},
		{
			[]string{"192.168.0.1/24", "192.168.1.1/24", "192.168.1.1/30"},
			[]string{"192.168.0.1/24", "192.168.1.1/24", "192.168.1.1/30"},
			"branch inserts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := NewPrefixTree()
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(*network)
				assert.NoError(t, err)
			}
			walk := trie.walkDepth()
			for _, network := range tc.expectedNetworksInDepthOrder {
				_, expected, _ := net.ParseCIDR(network)
				actual := <-walk
				assert.Equal(t, *expected, actual)
			}

			// Ensure no unexpected elements in trie.
			for network := range walk {
				assert.Nil(t, network)
			}
		})
	}
}

func TestRemove(t *testing.T) {
	cases := []struct {
		inserts                      []string
		removes                      []string
		expectedRemoves              []string
		expectedNetworksInDepthOrder []string
		name                         string
	}{
		{
			[]string{"192.168.0.1/24"},
			[]string{"192.168.0.1/24"},
			[]string{"192.168.0.1/24"},
			[]string{},
			"basic remove",
		},
		{
			[]string{"192.168.0.1/24", "192.168.0.1/25", "192.168.0.1/26"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/24", "192.168.0.1/26"},
			"remove path prefix",
		},
		{
			[]string{"192.168.0.1/24", "192.168.0.1/25", "192.168.0.64/26", "192.168.0.1/26"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/24", "192.168.0.1/26", "192.168.0.64/26"},
			"remove path prefix with more than 1 children",
		},
		{
			[]string{"192.168.0.1/24", "192.168.0.1/25"},
			[]string{"192.168.0.1/26"},
			[]string{""},
			[]string{"192.168.0.1/24", "192.168.0.1/25"},
			"remove non existant",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			trie := NewPrefixTree()
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(*network)
				assert.NoError(t, err)
			}
			for i, remove := range tc.removes {
				_, network, _ := net.ParseCIDR(remove)
				removed, err := trie.Remove(*network)
				assert.NoError(t, err)
				if str := tc.expectedRemoves[i]; str != "" {
					_, expectedRemove, _ := net.ParseCIDR(tc.expectedRemoves[i])
					assert.Equal(t, expectedRemove, removed)
				} else {
					assert.Nil(t, removed)
				}
			}
			walk := trie.walkDepth()
			for _, network := range tc.expectedNetworksInDepthOrder {
				_, expected, _ := net.ParseCIDR(network)
				actual := <-walk
				assert.Equal(t, *expected, actual)
			}

			// Ensure no unexpected elements in trie.
			for network := range walk {
				assert.Nil(t, network)
			}
		})
	}
}

type expectedIPRange struct {
	start net.IP
	end   net.IP
}

func TestContains(t *testing.T) {
	cases := []struct {
		inserts     []string
		expectedIPs []expectedIPRange
		name        string
	}{
		{
			[]string{"192.168.0.0/24"},
			[]expectedIPRange{
				expectedIPRange{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.1.0")},
			},
			"basic contains",
		},
		{
			[]string{"192.168.0.0/24", "128.168.0.0/24"},
			[]expectedIPRange{
				expectedIPRange{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.1.0")},
				expectedIPRange{net.ParseIP("128.168.0.0"), net.ParseIP("128.168.1.0")},
			},
			"multiple ranges contains",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := NewPrefixTree()
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(*network)
				assert.NoError(t, err)
			}
			for _, expectedIPRange := range tc.expectedIPs {
				var contains bool
				var err error
				start := expectedIPRange.start
				for ; !expectedIPRange.end.Equal(start); start = rnet.NextIP(start) {
					contains, err = trie.Contains(start)
					assert.NoError(t, err)
					assert.True(t, contains)
				}

				// Check out of bounds ips on both ends
				contains, err = trie.Contains(rnet.PreviousIP(expectedIPRange.start))
				assert.NoError(t, err)
				assert.False(t, contains)
				contains, err = trie.Contains(rnet.NextIP(expectedIPRange.end))
				assert.NoError(t, err)
				assert.False(t, contains)
			}
		})
	}
}

func TestContainingNetworks(t *testing.T) {
	cases := []struct {
		inserts  []string
		ip       net.IP
		networks []string
		name     string
	}{
		{
			[]string{"192.168.0.0/24"},
			net.ParseIP("192.168.0.1"),
			[]string{"192.168.0.0/24"},
			"basic containing networks",
		},
		{
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			net.ParseIP("192.168.0.1"),
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			"inclusive networks",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := NewPrefixTree()
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(*network)
				assert.NoError(t, err)
			}
			expectedNetworks := []net.IPNet{}
			for _, network := range tc.networks {
				_, net, _ := net.ParseCIDR(network)
				expectedNetworks = append(expectedNetworks, *net)
			}
			networks, err := trie.ContainingNetworks(tc.ip)
			assert.NoError(t, err)
			assert.Equal(t, expectedNetworks, networks)
		})
	}
}
