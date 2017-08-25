/*
Package ip provides utility functions for working with IPs (net.IP).
*/
package ip

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IP address uint32 components count.
const (
	IPv4Uint32Count = 1
	IPv6Uint32Count = 4

	BitsPerUint32 = 32
)

// NetworkNumber represents an IP address using uint32 as internal storage.
// IPv4 usings 1 uint32, while IPv6 uses 4 uint32.
type NetworkNumber []uint32

// NewNetworkNumber returns a equivalent NetworkNumber to given IP address,
// return nil if ip is neither IPv4 nor IPv6.
func NewNetworkNumber(ip net.IP) NetworkNumber {
	if ip == nil {
		return nil
	}
	coercedIP := ip.To4()
	parts := 1
	if coercedIP == nil {
		coercedIP = ip.To16()
		parts = 4
	}
	if coercedIP == nil {
		return nil
	}
	nn := make(NetworkNumber, parts)
	for i := 0; i < parts; i++ {
		idx := i * net.IPv4len
		nn[i] = binary.BigEndian.Uint32(coercedIP[idx : idx+net.IPv4len])
	}
	return nn
}

// ToV4 returns ip address if ip is IPv4, returns nil otherwise.
func (n NetworkNumber) ToV4() NetworkNumber {
	if len(n) != IPv4Uint32Count {
		return nil
	}
	return n
}

// ToV6 returns ip address if ip is IPv6, returns nil otherwise.
func (n NetworkNumber) ToV6() NetworkNumber {
	if len(n) != IPv6Uint32Count {
		return nil
	}
	return n
}

// Bit returns uint32 representing the bit value at given position, e.g.,
// "128.0.0.0" has bit value of 1 at position 31, and 0 for positions 30 to 0.
func (n NetworkNumber) Bit(position uint) (uint32, error) {
	if int(position) > len(n)*BitsPerUint32-1 {
		return 0, ErrInvalidBitPosition
	}
	idx := len(n) - 1
	for ; position >= BitsPerUint32; position -= BitsPerUint32 {
		idx--
	}
	lShift := position
	mask := uint32(1) << lShift
	return (n[idx] & mask) >> lShift, nil
}

// ErrNotIPv4Error is returned when IPv4 operations is performed on IPv6.
var ErrNotIPv4Error = fmt.Errorf("IP is not IPv4")

// ErrInvalidBitPosition is returned when bits requested is not valid.
var ErrInvalidBitPosition = fmt.Errorf("bit position not valid")

const ipv4BitLength = 32

// IPv4ToUint32 converts ipV4 to uint32.
func IPv4ToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, ErrNotIPv4Error
	}
	return binary.BigEndian.Uint32(ip), nil
}

// Uint32ToIPv4 converts uint32 to ipV4 net.IP.
func Uint32ToIPv4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// IPv4BitsAsUint returns uint32 representing bits at position of length
// numberOfBits, position is a number in [0, 31] representing the starting
// position in ip, with 31 being the most significant bit.
// E.g.,
// 		"128.0.0.0" has bit value of 1 at the 31th bit.
func IPv4BitsAsUint(ip uint32, position uint8, numberOfBits uint8) (uint32, error) {
	if numberOfBits == 0 || numberOfBits > ipv4BitLength || position > ipv4BitLength-1 {
		return 0, ErrInvalidBitPosition
	}
	if numberOfBits-1 > position {
		return 0, ErrInvalidBitPosition
	}
	lShift := position - (numberOfBits - 1)
	mask := (uint32(1)<<numberOfBits - 1) << lShift
	return (ip & mask) >> lShift, nil
}

// NextIP returns the next sequential ip.
func NextIP(ip net.IP) net.IP {
	newIP := make([]byte, len(ip))
	copy(newIP, ip)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] > 0 {
			break
		}
	}
	return newIP
}

// PreviousIP returns the previous sequential ip.
func PreviousIP(ip net.IP) net.IP {
	newIP := make([]byte, len(ip))
	copy(newIP, ip)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]--
		if newIP[i] < 255 {
			break
		}
	}
	return newIP
}
