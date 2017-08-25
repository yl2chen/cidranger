package ip

import (
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

func TestIPv4ToUint32(t *testing.T) {
	cases := []struct {
		ip          string
		ipUint32    uint32
		expectedErr error
	}{
		{"0.0.0.1", 1, nil},
		{"1.0.0.0", 16777216, nil},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", 0, ErrNotIPv4Error},
	}

	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			ret, err := IPv4ToUint32(net.ParseIP(c.ip))
			assert.Equal(t, c.expectedErr, err)
			assert.Equal(t, c.ipUint32, ret)
		})
	}
}

func TestUint32ToIPv4(t *testing.T) {
	cases := []struct {
		ip       uint32
		expected net.IP
		name     string
	}{
		{2147483648, net.ParseIP("128.0.0.0").To4(), "128.0.0.0"},
		{2147483649, net.ParseIP("128.0.0.1").To4(), "128.0.0.1"},
		{4294967295, net.ParseIP("255.255.255.255").To4(), "255.255.255.255"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, Uint32ToIPv4(tc.ip))
		})
	}
}

func TestIPv4BitsAsUint(t *testing.T) {
	cases := []struct {
		ip           string
		ipUint32     uint32
		position     uint8
		bits         uint8
		expectedBits uint32
		expectedErr  error
	}{
		{"0.0.0.1", 1, 0, 0, 0, ErrInvalidBitPosition},
		{"0.0.0.1", 1, 0, 2, 0, ErrInvalidBitPosition},
		{"0.0.0.1", 1, 0, 33, 0, ErrInvalidBitPosition},
		{"0.0.0.1", 1, 32, 1, 0, ErrInvalidBitPosition},
		{"0.0.0.1", 1, 0, 1, 1, nil},
		{"0.0.0.1", 1, 1, 2, 1, nil},
		{"0.0.0.1", 1, 2, 1, 0, nil},
		{"1.0.0.0", 16777216, 24, 1, 1, nil},
		{"1.0.0.0", 16777216, 24, 2, 2, nil},
		{"1.0.0.0", 16777216, 24, 3, 4, nil},
		{"1.0.0.0", 16777216, 24, 25, 16777216, nil},
	}
	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			ret, err := IPv4BitsAsUint(c.ipUint32, c.position, c.bits)
			assert.Equal(t, c.expectedErr, err)
			assert.Equal(t, c.expectedBits, ret)
		})
	}
}

// TODO: add test cases for ipV6
func TestNextIP(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.0", "0.0.0.1", "basic"},
		{"0.0.0.255", "0.0.1.0", "rollover"},
		{"0.255.255.255", "1.0.0.0", "consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, net.ParseIP(tc.next), NextIP(net.ParseIP(tc.ip)))
		})
	}
}

// TODO: add test cases for ipV6
func TestPreviousIP(t *testing.T) {
	cases := []struct {
		ip   string
		next string
		name string
	}{
		{"0.0.0.1", "0.0.0.0", "basic"},
		{"0.0.1.0", "0.0.0.255", "rollover"},
		{"1.0.0.0", "0.255.255.255", "consecutive rollover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, net.ParseIP(tc.next), PreviousIP(net.ParseIP(tc.ip)))
		})
	}
}
