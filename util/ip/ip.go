/*
Package ip provides utility functions for working with IPs (net.IP).
*/
package ip

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ErrNotIPv4Error is returned when IPv4 operations is performed on IPv6.
var ErrNotIPv4Error = fmt.Errorf("IP is not IPv4")

// ErrBitsNotValid is returned when bits requested is not valid.
var ErrBitsNotValid = fmt.Errorf("bits requested not valid")

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
		return 0, ErrBitsNotValid
	}
	if numberOfBits-1 > position {
		return 0, ErrBitsNotValid
	}
	shiftLeft := position - (numberOfBits - 1)
	mask := (uint32(1)<<numberOfBits - 1) << shiftLeft
	return (ip & mask) >> shiftLeft, nil
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
