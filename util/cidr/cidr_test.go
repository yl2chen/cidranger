package cidr

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yl2chen/cidranger/util/ip"
)

func TestGreatestCommonBitPosition(t *testing.T) {
	cases := []struct {
		cidr1       string
		cidr2       string
		expectedPos uint8
		expectedErr error
	}{
		{"0.0.1.0/24", "0.0.0.0/24", uint8(9), nil},
		{"0.0.0.0/24", "0.0.0.0/24", uint8(8), nil},
		{"128.0.0.0/24", "0.0.0.0/24", 0, ErrNoGreatestCommonBit},
		{"128.0.0.0/24", "192.0.0.0/16", uint8(31), nil},
		{"128.0.0.0/24", "128.0.0.0/16", uint8(16), nil},
		{"128.0.0.0/24", "128.1.0.0/16", uint8(17), nil},
	}
	for _, c := range cases {
		_, cidr1, err := net.ParseCIDR(c.cidr1)
		assert.NoError(t, err)
		_, cidr2, err := net.ParseCIDR(c.cidr2)
		assert.NoError(t, err)
		pos, err := GreatestCommonBitPosition(cidr1, cidr2)
		if c.expectedErr != nil {
			assert.Equal(t, c.expectedErr, err)
		} else {
			assert.Equal(t, c.expectedPos, pos)
		}
	}
}

func TestMaskNetwork(t *testing.T) {
	cases := []struct {
		network       string
		mask          int
		maskedNetwork string
	}{
		{"192.168.0.0/16", 16, "192.168.0.0/16"},
		{"192.168.0.0/16", 14, "192.168.0.0/14"},
		{"192.168.0.0/16", 18, "192.168.0.0/18"},
		{"192.168.0.0/16", 8, "192.0.0.0/8"},
	}
	for _, testcase := range cases {
		_, network, err := net.ParseCIDR(testcase.network)
		assert.NoError(t, err)
		_, expected, err := net.ParseCIDR(testcase.maskedNetwork)
		assert.NoError(t, err)
		assert.Equal(t, expected, MaskNetwork(network, testcase.mask))
	}
}

func TestIPsInNetwork(t *testing.T) {
	cases := []struct {
		network string
		start   net.IP
		end     net.IP
		name    string
	}{
		{
			"192.168.0.0/30",
			net.ParseIP("192.168.0.0"),
			net.ParseIP("192.168.0.4"),
			"IPs for 192.168.0.0/30",
		},
		{
			"192.168.0.0/29",
			net.ParseIP("192.168.0.0"),
			net.ParseIP("192.168.0.8"),
			"IPs for 192.168.0.0/29",
		},
		{
			"192.168.0.0/24",
			net.ParseIP("192.168.0.0"),
			net.ParseIP("192.168.1.0"),
			"IPs for 192.168.0.0/24",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, network, err := net.ParseCIDR(tc.network)
			assert.NoError(t, err)
			ips := IPsInNetwork(*network)
			start := tc.start
			for actual := range ips {
				assert.Equal(t, start, actual.To16())
				start = ip.NextIP(start)
			}
			assert.Equal(t, tc.end, start)
		})
	}
}
