package net

import (
	"math"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNetworkNumber(t *testing.T) {
	cases := []struct {
		ip   net.IP
		nn   NetworkNumber
		name string
	}{
		{nil, nil, "nil input"},
		{net.IP([]byte{1, 1, 1, 1, 1}), nil, "bad input"},
		{net.ParseIP("128.0.0.0"), NetworkNumber([]uint32{2147483648}), "IPv4"},
		{
			net.ParseIP("2001:0db8::ff00:0042:8329"),
			NetworkNumber([]uint32{536939960, 0, 65280, 4358953}),
			"IPv6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.nn, NewNetworkNumber(tc.ip))
		})
	}
}

func TestNetworkNumberAssertion(t *testing.T) {
	cases := []struct {
		ip   NetworkNumber
		to4  NetworkNumber
		to6  NetworkNumber
		name string
	}{
		{NetworkNumber([]uint32{1}), NetworkNumber([]uint32{1}), nil, "is IPv4"},
		{NetworkNumber([]uint32{1, 1, 1, 1}), nil, NetworkNumber([]uint32{1, 1, 1, 1}), "is IPv6"},
		{NetworkNumber([]uint32{1, 1}), nil, nil, "is invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.to4, tc.ip.ToV4())
			assert.Equal(t, tc.to6, tc.ip.ToV6())
		})
	}
}

func TestNetworkNumberBit(t *testing.T) {
	cases := []struct {
		ip   NetworkNumber
		ones map[uint]bool
		name string
	}{
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), map[uint]bool{31: true}, "128.0.0.0"},
		{NewNetworkNumber(net.ParseIP("1.1.1.1")), map[uint]bool{0: true, 8: true, 16: true, 24: true}, "1.1.1.1"},
		{NewNetworkNumber(net.ParseIP("8000::")), map[uint]bool{127: true}, "8000::"},
		{NewNetworkNumber(net.ParseIP("8000::8000")), map[uint]bool{127: true, 15: true}, "8000::8000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := uint(0); i < uint(len(tc.ip)*BitsPerUint32); i++ {
				bit, err := tc.ip.Bit(i)
				assert.NoError(t, err)
				if _, isOne := tc.ones[i]; isOne {
					assert.Equal(t, uint32(1), bit)
				} else {
					assert.Equal(t, uint32(0), bit)
				}
			}
		})
	}
}

func TestNetworkNumberBitError(t *testing.T) {
	cases := []struct {
		ip       NetworkNumber
		position uint
		err      error
		name     string
	}{
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), 0, nil, "IPv4 index in bound"},
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), 31, nil, "IPv4 index in bound"},
		{NewNetworkNumber(net.ParseIP("128.0.0.0")), 32, ErrInvalidBitPosition, "IPv4 index out of bounds"},
		{NewNetworkNumber(net.ParseIP("8000::")), 0, nil, "IPv6 index in bound"},
		{NewNetworkNumber(net.ParseIP("8000::")), 127, nil, "IPv6 index in bound"},
		{NewNetworkNumber(net.ParseIP("8000::")), 128, ErrInvalidBitPosition, "IPv6 index out of bounds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ip.Bit(tc.position)
			assert.Equal(t, tc.err, err)
		})
	}
}

func TestNetworkNumberEqual(t *testing.T) {
	cases := []struct {
		n1     NetworkNumber
		n2     NetworkNumber
		equals bool
		name   string
	}{
		{NetworkNumber{math.MaxUint32}, NetworkNumber{math.MaxUint32}, true, "IPv4 equals"},
		{NetworkNumber{math.MaxUint32}, NetworkNumber{math.MaxUint32 - 1}, false, "IPv4 does not equal"},
		{NetworkNumber{1, 1, 1, 1}, NetworkNumber{1, 1, 1, 1}, true, "IPv6 equals"},
		{NetworkNumber{1, 1, 1, 1}, NetworkNumber{1, 1, 1, 2}, false, "IPv6 does not equal"},
		{NetworkNumber{1}, NetworkNumber{1, 2, 3, 4}, false, "Version mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.equals, tc.n1.Equal(tc.n2))
		})
	}
}

func TestNetworkNumberNext(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.0", "0.0.0.1", "IPv4 basic"},
		{"0.0.0.255", "0.0.1.0", "IPv4 rollover"},
		{"0.255.255.255", "1.0.0.0", "IPv4 consecutive rollover"},
		{"8000::0", "8000::1", "IPv6 basic"},
		{"0::ffff", "0::1:0", "IPv6 rollover"},
		{"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1::", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := NewNetworkNumber(net.ParseIP(tc.ip))
			expected := NewNetworkNumber(net.ParseIP(tc.next))
			assert.Equal(t, expected, ip.Next())
		})
	}
}

func TestNeworkNumberPrevious(t *testing.T) {
	cases := []struct {
		ip       string
		previous string
		name     string
	}{
		{"0.0.0.1", "0.0.0.0", "IPv4 basic"},
		{"0.0.1.0", "0.0.0.255", "IPv4 rollover"},
		{"1.0.0.0", "0.255.255.255", "IPv4 consecutive rollover"},
		{"8000::1", "8000::0", "IPv6 basic"},
		{"0::1:0", "0::ffff", "IPv6 rollover"},
		{"1::0", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := NewNetworkNumber(net.ParseIP(tc.ip))
			expected := NewNetworkNumber(net.ParseIP(tc.previous))
			assert.Equal(t, expected, ip.Previous())
		})
	}
}

func TestLeastCommonBitPositionForNetworks(t *testing.T) {
	cases := []struct {
		ip1      NetworkNumber
		ip2      NetworkNumber
		position uint
		err      error
		name     string
	}{
		{
			NetworkNumber([]uint32{2147483648}),
			NetworkNumber([]uint32{3221225472, 0, 0, 0}),
			0, ErrVersionMismatch, "Version mismatch",
		},
		{
			NetworkNumber([]uint32{2147483648}),
			NetworkNumber([]uint32{3221225472}),
			31, nil, "IPv4 31st position",
		},
		{
			NetworkNumber([]uint32{2147483648}),
			NetworkNumber([]uint32{2147483648}),
			0, nil, "IPv4 0th position",
		},
		{
			NetworkNumber([]uint32{2147483648}),
			NetworkNumber([]uint32{1}),
			0, ErrNoGreatestCommonBit, "IPv4 diverge at first bit",
		},
		{
			NetworkNumber([]uint32{2147483648, 0, 0, 0}),
			NetworkNumber([]uint32{3221225472, 0, 0, 0}),
			127, nil, "IPv6 127th position",
		},
		{
			NetworkNumber([]uint32{2147483648, 1, 1, 1}),
			NetworkNumber([]uint32{2147483648, 1, 1, 1}),
			0, nil, "IPv6 0th position",
		},
		{
			NetworkNumber([]uint32{2147483648, 0, 0, 0}),
			NetworkNumber([]uint32{0, 0, 0, 1}),
			0, ErrNoGreatestCommonBit, "IPv6 diverge at first bit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, err := tc.ip1.LeastCommonBitPosition(tc.ip2)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.position, pos)
		})
	}
}

func TestNewNetwork(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.128.0.0/24")
	n := NewNetwork(*ipNet)

	assert.Equal(t, *ipNet, n.IPNet)
	assert.Equal(t, NetworkNumber{3229614080}, n.Number)
	assert.Equal(t, NetworkNumberMask{math.MaxUint32 - uint32(math.MaxUint8)}, n.Mask)
}

func TestNetworkMasked(t *testing.T) {
	cases := []struct {
		network       string
		mask          int
		maskedNetwork string
	}{
		{"192.168.0.0/16", 16, "192.168.0.0/16"},
		{"192.168.0.0/16", 14, "192.168.0.0/14"},
		{"192.168.0.0/16", 18, "192.168.0.0/18"},
		{"192.168.0.0/16", 8, "192.0.0.0/8"},
		{"8000::/128", 96, "8000::/96"},
		{"8000::/128", 128, "8000::/128"},
		{"8000::/96", 112, "8000::/112"},
		{"8000:ffff::/96", 16, "8000::/16"},
	}
	for _, testcase := range cases {
		_, network, _ := net.ParseCIDR(testcase.network)
		_, expected, _ := net.ParseCIDR(testcase.maskedNetwork)
		n1 := NewNetwork(*network)
		e1 := NewNetwork(*expected)
		assert.True(t, e1.String() == n1.Masked(testcase.mask).String())
	}
}

func TestNetworkEqual(t *testing.T) {
	cases := []struct {
		n1    string
		n2    string
		equal bool
		name  string
	}{
		{"192.128.0.0/24", "192.128.0.0/24", true, "IPv4 equals"},
		{"192.128.0.0/24", "192.128.0.0/23", false, "IPv4 not equals"},
		{"8000::/24", "8000::/24", true, "IPv6 equals"},
		{"8000::/24", "8000::/23", false, "IPv6 not equals"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ipNet1, _ := net.ParseCIDR(tc.n1)
			_, ipNet2, _ := net.ParseCIDR(tc.n2)
			assert.Equal(t, tc.equal, NewNetwork(*ipNet1).Equal(NewNetwork(*ipNet2)))
		})
	}
}

func TestNetworkContains(t *testing.T) {
	cases := []struct {
		network string
		firstIP string
		lastIP  string
		name    string
	}{
		{"192.168.0.0/24", "192.168.0.0", "192.168.0.255", "192.168.0.0/24 contains"},
		{"8000::0/120", "8000::0", "8000::ff", "8000::0/120 contains"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, net1, _ := net.ParseCIDR(tc.network)
			network := NewNetwork(*net1)
			ip := NewNetworkNumber(net.ParseIP(tc.firstIP))
			lastIP := NewNetworkNumber(net.ParseIP(tc.lastIP))
			assert.False(t, network.Contains(ip.Previous()))
			assert.False(t, network.Contains(lastIP.Next()))
			for ; !ip.Equal(lastIP.Next()); ip = ip.Next() {
				assert.True(t, network.Contains(ip))
			}
		})
	}
}

func TestNetworkContainsVersionMismatch(t *testing.T) {
	cases := []struct {
		network string
		ip      string
		name    string
	}{
		{"192.168.0.0/24", "8000::0", "IPv6 in IPv4 network"},
		{"8000::0/120", "192.168.0.0", "IPv4 in IPv6 network"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, net1, _ := net.ParseCIDR(tc.network)
			network := NewNetwork(*net1)
			assert.False(t, network.Contains(NewNetworkNumber(net.ParseIP(tc.ip))))
		})
	}
}

func TestNetworkCovers(t *testing.T) {
	cases := []struct {
		network string
		covers  string
		result  bool
		name    string
	}{
		{"10.0.0.0/24", "10.0.0.1/25", true, "contains"},
		{"10.0.0.0/24", "11.0.0.1/25", false, "not contains"},
		{"10.0.0.0/16", "10.0.0.0/15", false, "prefix false"},
		{"10.0.0.0/15", "10.0.0.0/16", true, "prefix true"},
		{"10.0.0.0/15", "10.0.0.0/15", true, "same"},
		{"10::0/15", "10.0.0.0/15", false, "ip version mismatch"},
		{"10::0/15", "10::0/16", true, "ipv6"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, n, _ := net.ParseCIDR(tc.network)
			network := NewNetwork(*n)
			_, n, _ = net.ParseCIDR(tc.covers)
			covers := NewNetwork(*n)
			assert.Equal(t, tc.result, network.Covers(covers))
		})
	}
}

func TestNetworkLeastCommonBitPosition(t *testing.T) {
	cases := []struct {
		cidr1       string
		cidr2       string
		expectedPos uint
		expectedErr error
		name        string
	}{
		{"0.0.1.0/24", "0.0.0.0/24", uint(9), nil, "IPv4 diverge before mask pos"},
		{"0.0.0.0/24", "0.0.0.0/24", uint(8), nil, "IPv4 diverge after mask pos"},
		{"0.0.0.128/24", "0.0.0.0/16", uint(16), nil, "IPv4 different mask pos"},
		{"128.0.0.0/24", "0.0.0.0/24", 0, ErrNoGreatestCommonBit, "IPv4 diverge at 1st pos"},
		{"8000::/96", "8000::1:0:0/96", uint(33), nil, "IPv6 diverge before mask pos"},
		{"8000::/96", "8000::8:0/96", uint(32), nil, "IPv6 diverge after mask pos"},
		{"8000::/96", "8000::/95", uint(33), nil, "IPv6 different mask pos"},
		{"ffff::0/24", "0::1/24", 0, ErrNoGreatestCommonBit, "IPv6 diverge at 1st pos"},
	}
	for _, c := range cases {
		_, cidr1, err := net.ParseCIDR(c.cidr1)
		assert.NoError(t, err)
		_, cidr2, err := net.ParseCIDR(c.cidr2)
		assert.NoError(t, err)
		n1 := NewNetwork(*cidr1)
		pos, err := n1.LeastCommonBitPosition(NewNetwork(*cidr2))
		if c.expectedErr != nil {
			assert.Equal(t, c.expectedErr, err)
		} else {
			assert.Equal(t, c.expectedPos, pos)
		}
	}
}

func TestMask(t *testing.T) {
	cases := []struct {
		mask   NetworkNumberMask
		ip     NetworkNumber
		masked NetworkNumber
		err    error
		name   string
	}{
		{NetworkNumberMask{math.MaxUint32}, NetworkNumber{math.MaxUint32}, NetworkNumber{math.MaxUint32}, nil, "nop IPv4 mask"},
		{NetworkNumberMask{math.MaxUint32 - math.MaxUint16}, NetworkNumber{math.MaxUint16 + 1}, NetworkNumber{math.MaxUint16 + 1}, nil, "nop IPv4 mask"},
		{NetworkNumberMask{math.MaxUint32 - math.MaxUint16}, NetworkNumber{math.MaxUint32}, NetworkNumber{math.MaxUint32 - math.MaxUint16}, nil, "IPv4 masked"},
		{NetworkNumberMask{math.MaxUint32, 0, 0, 0}, NetworkNumber{math.MaxUint32, 0, 0, 0}, NetworkNumber{math.MaxUint32, 0, 0, 0}, nil, "nop IPv6 mask"},
		{NetworkNumberMask{math.MaxUint32 - math.MaxUint16, 0, 0, 0}, NetworkNumber{math.MaxUint16 + 1, 0, 0, 0}, NetworkNumber{math.MaxUint16 + 1, 0, 0, 0}, nil, "nop IPv6 mask"},
		{NetworkNumberMask{math.MaxUint32 - math.MaxUint16, 0, 0, 0}, NetworkNumber{math.MaxUint32, 0, 0, 0}, NetworkNumber{math.MaxUint32 - math.MaxUint16, 0, 0, 0}, nil, "IPv6 masked"},
		{NetworkNumberMask{math.MaxUint32}, NetworkNumber{math.MaxUint32, 0}, nil, ErrVersionMismatch, "Version mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			masked, err := tc.mask.Mask(tc.ip)
			assert.Equal(t, tc.masked, masked)
			assert.Equal(t, tc.err, err)
		})
	}
}

func TestNextIP(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.0", "0.0.0.1", "IPv4 basic"},
		{"0.0.0.255", "0.0.1.0", "IPv4 rollover"},
		{"0.255.255.255", "1.0.0.0", "IPv4 consecutive rollover"},
		{"8000::0", "8000::1", "IPv6 basic"},
		{"0::ffff", "0::1:0", "IPv6 rollover"},
		{"0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1::", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, net.ParseIP(tc.next), NextIP(net.ParseIP(tc.ip)))
		})
	}
}

func TestPreviousIP(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.1", "0.0.0.0", "IPv4 basic"},
		{"0.0.1.0", "0.0.0.255", "IPv4 rollover"},
		{"1.0.0.0", "0.255.255.255", "IPv4 consecutive rollover"},
		{"8000::1", "8000::0", "IPv6 basic"},
		{"0::1:0", "0::ffff", "IPv6 rollover"},
		{"1::0", "0:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "IPv6 consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, net.ParseIP(tc.next), PreviousIP(net.ParseIP(tc.ip)))
		})
	}
}

/*
 *********************************
 Benchmarking ip manipulations.
 *********************************
*/
func BenchmarkNetworkNumberBitIPv4(b *testing.B) {
	benchmarkNetworkNumberBit(b, "52.95.110.1", 6)
}
func BenchmarkNetworkNumberBitIPv6(b *testing.B) {
	benchmarkNetworkNumberBit(b, "2600:1ffe:e000::", 44)
}

func BenchmarkNetworkNumberEqualIPv4(b *testing.B) {
	benchmarkNetworkNumberEqual(b, "52.95.110.1", "52.95.110.1")
}

func BenchmarkNetworkNumberEqualIPv6(b *testing.B) {
	benchmarkNetworkNumberEqual(b, "2600:1ffe:e000::", "2600:1ffe:e000::")
}

func BenchmarkNetworkContainsIPv4(b *testing.B) {
	benchmarkNetworkContains(b, "52.95.110.0/24", "52.95.110.1")
}

func BenchmarkNetworkContainsIPv6(b *testing.B) {
	benchmarkNetworkContains(b, "2600:1ffe:e000::/40", "2600:1ffe:f000::")
}

func benchmarkNetworkNumberBit(b *testing.B, ip string, pos uint) {
	nn := NewNetworkNumber(net.ParseIP(ip))
	for n := 0; n < b.N; n++ {
		nn.Bit(pos)
	}
}

func benchmarkNetworkNumberEqual(b *testing.B, ip1 string, ip2 string) {
	nn1 := NewNetworkNumber(net.ParseIP(ip1))
	nn2 := NewNetworkNumber(net.ParseIP(ip2))
	for n := 0; n < b.N; n++ {
		nn1.Equal(nn2)
	}
}

func benchmarkNetworkContains(b *testing.B, cidr string, ip string) {
	nn := NewNetworkNumber(net.ParseIP(ip))
	_, ipNet, _ := net.ParseCIDR(cidr)
	network := NewNetwork(*ipNet)
	for n := 0; n < b.N; n++ {
		network.Contains(nn)
	}
}
