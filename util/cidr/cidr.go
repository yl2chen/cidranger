package cidr

import (
	"fmt"
	"net"

	"github.com/yl2chen/cidranger/util/ip"
)

// ErrNoGreatestCommonBit is an error returned when no greatest common bit
// exists for the cidr ranges.
var ErrNoGreatestCommonBit = fmt.Errorf("No greatest common bit")

// GreatestCommonBitPosition returns the greatest common bit position of
// given cidr blocks.
func GreatestCommonBitPosition(network1 *net.IPNet, network2 *net.IPNet) (uint8, error) {
	ip1, err := ip.IPv4ToBigEndianUint32(network1.IP)
	if err != nil {
		return 0, err
	}
	ip2, err := ip.IPv4ToBigEndianUint32(network2.IP)
	if err != nil {
		return 0, err
	}
	maskSize, _ := network1.Mask.Size()
	if maskSize2, _ := network2.Mask.Size(); maskSize2 < maskSize {
		maskSize = maskSize2
	}
	mask := uint32(1) << 31
	if ip1&mask != ip2&mask {
		return 0, ErrNoGreatestCommonBit
	}
	var i = 1
	for ; i < maskSize; i++ {
		mask = mask >> 1
		if ip1&mask != ip2&mask {
			break
		}
	}
	return uint8(31 - i + 1), nil
}

// MaskNetwork returns a copy of given network with new mask.
func MaskNetwork(network *net.IPNet, ones int) *net.IPNet {
	mask := net.CIDRMask(ones, 32)
	return &net.IPNet{
		IP:   network.IP.Mask(mask),
		Mask: mask,
	}
}

// IPsInNetwork returns a channel that generates all ips in given network.
func IPsInNetwork(network net.IPNet) <-chan net.IP {
	ipChannel := make(chan net.IP)
	startingIP := network.IP
	ones, bits := network.Mask.Size()
	networkSize := 1 << uint(bits-ones)
	go func() {
		for i := 0; i < networkSize; i++ {
			ipChannel <- startingIP
			startingIP = ip.NextIP(startingIP)
		}
		close(ipChannel)
	}()
	return ipChannel
}
