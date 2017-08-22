package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		{"0.0.0.1", 1, 0, 0, 0, ErrBitsNotValid},
		{"0.0.0.1", 1, 0, 2, 0, ErrBitsNotValid},
		{"0.0.0.1", 1, 0, 33, 0, ErrBitsNotValid},
		{"0.0.0.1", 1, 32, 1, 0, ErrBitsNotValid},
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
