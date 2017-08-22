/*
Package trie provides an LPC (Level Path Compressed) trie implementation of the
ranger interface inspired by this blog post:
https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux

CIDR blocks are stored using a prefix tree structure where each node has its
parent as prefix, and the path from the root node represents current CIDR block.

For IPv4, the trie structure guarantees max depth of 32 as IPv4 addresses are
32 bits long and each bit represents a prefix tree starting at that bit. This
property also gaurantees constant lookup time in Big-O notation.

Path compression compresses a string of node with only 1 child into a single
node, decrease the amount of lookups necessary during containment tests.

Level compression dictates the amount of direct children of a node by allowing
it to handle multiple bits in the path.  The heuristic (based on children
population) to decide when the compression and decompression happens is outlined
in the prior linked blog, and will be experimented with in more depth in this
project in the future.

TODO: Implement level-compressed component of the LPC trie.
TODO: Add support for ipV6.

*/
package trie

import (
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/yl2chen/cidranger/util/cidr"
	iputil "github.com/yl2chen/cidranger/util/ip"
)

// PrefixTrie is a level-path-compressed (LPC) trie for cidr ranges.
// TODO: Implement level-compressed capability
type PrefixTrie struct {
	parent   *PrefixTrie
	children []*PrefixTrie

	numBitsSkipped uint8
	numBitsHandled uint8

	network       *net.IPNet
	networkNumber uint32
	networkMask   uint32
	hasEntry      bool
}

// NewPrefixTree creates a new PrefixTrie.
func NewPrefixTree() *PrefixTrie {
	_, rootCidr, _ := net.ParseCIDR("0.0.0.0/0")
	return &PrefixTrie{
		children:       make([]*PrefixTrie, 2, 2),
		numBitsSkipped: 0,
		numBitsHandled: 1,
		network:        rootCidr,
	}
}

func newPathPrefixTrie(network *net.IPNet, numBitsSkipped uint8) (*PrefixTrie, error) {
	path := NewPrefixTree()
	path.numBitsSkipped = numBitsSkipped
	path.network = cidr.MaskNetwork(network, int(numBitsSkipped))
	networkNumber, err := iputil.IPv4ToUint32(path.network.IP)
	if err != nil {
		return nil, err
	}
	path.networkNumber = networkNumber
	path.networkMask = math.MaxUint32 << uint32(32-numBitsSkipped)
	return path, nil
}

func newEntryTrie(network *net.IPNet) (*PrefixTrie, error) {
	ones, _ := network.Mask.Size()
	leaf, err := newPathPrefixTrie(network, uint8(ones))
	if err != nil {
		return nil, err
	}
	leaf.hasEntry = true
	return leaf, nil
}

// Insert inserts the given cidr range into prefix trie.
func (p *PrefixTrie) Insert(network net.IPNet) error {
	networkNumber, err := iputil.IPv4ToUint32(network.IP)
	if err != nil {
		return err
	}
	return p.insert(&network, networkNumber)
}

// Remove removes network from trie.
func (p *PrefixTrie) Remove(network net.IPNet) (*net.IPNet, error) {
	networkNumber, err := iputil.IPv4ToUint32(network.IP)
	if err != nil {
		return nil, err
	}
	return p.remove(&network, networkNumber)
}

func (p *PrefixTrie) remove(network *net.IPNet, networkNumber uint32) (*net.IPNet, error) {
	if p.hasEntry && p.networkEquals(network) {
		if p.childrenCount() > 1 {
			p.hasEntry = false
		} else {
			// Has 0 or 1 child.
			parentBits, err := p.parent.targetBitsFromIP(networkNumber)
			if err != nil {
				return nil, err
			}
			var skipChild *PrefixTrie
			for _, child := range p.children {
				if child != nil {
					skipChild = child
					break
				}
			}
			p.parent.children[parentBits] = skipChild
		}
		return network, nil
	}
	bits, err := p.targetBitsFromIP(networkNumber)
	if err != nil {
		return nil, err
	}
	child := p.children[bits]
	if child != nil {
		return child.remove(network, networkNumber)
	}
	return nil, nil
}

func (p *PrefixTrie) childrenCount() int {
	count := 0
	for _, child := range p.children {
		if child != nil {
			count++
		}
	}
	return count
}

// Contains returns boolean indicating whether given ip is contained in any
// of the inserted networks.
func (p *PrefixTrie) Contains(ip net.IP) (bool, error) {
	ipUint32, err := iputil.IPv4ToUint32(ip)
	if err != nil {
		return false, err
	}
	networks, err := p.containingNetworks(ipUint32, false)
	if err != nil {
		return false, err
	}
	return len(networks) > 0, nil
}

// ContainingNetworks returns the list of networks given ip is a part of in
// ascending prefix order.
func (p *PrefixTrie) ContainingNetworks(ip net.IP) ([]net.IPNet, error) {
	ipUint32, err := iputil.IPv4ToUint32(ip)
	if err != nil {
		return nil, err
	}
	return p.containingNetworks(ipUint32, true)
}

// String returns string representation of trie, mainly for visualization and
// debugging.
func (p *PrefixTrie) String() string {
	children := []string{}
	padding := strings.Repeat("| ", p.level()+1)
	for bits, child := range p.children {
		if child == nil {
			continue
		}
		childStr := fmt.Sprintf("\n%s%d--> %s", padding, bits, child.String())
		children = append(children, childStr)
	}
	return fmt.Sprintf("%s (target_pos:%d:has_entry:%t)%s", p.network,
		p.targetBitPosition(), p.hasEntry, strings.Join(children, ""))
}

func (p *PrefixTrie) containingNetworks(ip uint32, greedy bool) ([]net.IPNet, error) {
	results := []net.IPNet{}
	if !p.contains(ip) {
		return results, nil
	}
	if p.hasEntry {
		results = append(results, *p.network)
		if !greedy {
			// If solution is not greedy, return first matched network.
			return results, nil
		}
	}
	bits, err := p.targetBitsFromIP(ip)
	if err != nil {
		return nil, err
	}
	child := p.children[bits]
	if child != nil {
		ranges, err := child.containingNetworks(ip, greedy)
		if err != nil {
			return nil, err
		}
		results = append(results, ranges...)
	}
	return results, nil
}

func (p *PrefixTrie) insert(network *net.IPNet, networkNumber uint32) error {
	if p.networkEquals(network) {
		p.hasEntry = true
		return nil
	}
	bits, err := p.targetBitsFromIP(networkNumber)
	if err != nil {
		return err
	}
	child := p.children[bits]
	if child == nil {
		var entry *PrefixTrie
		entry, err = newEntryTrie(network)
		if err != nil {
			return err
		}
		return p.insertPrefix(bits, entry)
	}

	greatestCommonPosition, err := cidr.GreatestCommonBitPosition(network, child.network)
	if err != nil {
		return err
	}
	if greatestCommonPosition-1 > child.targetBitPosition() {
		child, err = newPathPrefixTrie(network, 32-greatestCommonPosition)
		if err != nil {
			return err
		}
		err := p.insertPrefix(bits, child)
		if err != nil {
			return err
		}
	}
	return child.insert(network, networkNumber)
}

func (p *PrefixTrie) contains(ip uint32) bool {
	return ip&p.networkMask == p.networkNumber
}

func (p *PrefixTrie) insertPrefix(bits uint32, prefix *PrefixTrie) error {
	child := p.children[bits]
	if child != nil {
		prefixBits, err := prefix.targetBitsFromIP(child.networkNumber)
		if err != nil {
			return err
		}
		prefix.insertPrefix(prefixBits, child)
	}
	p.children[bits] = prefix
	prefix.parent = p
	return nil
}

func (p *PrefixTrie) targetBitPosition() uint8 {
	return 31 - p.numBitsSkipped
}

func (p *PrefixTrie) networkEquals(network *net.IPNet) bool {
	return p.network.String() == network.String()
}

func (p *PrefixTrie) targetBitsFromIP(ip uint32) (uint32, error) {
	return iputil.IPv4BitsAsUint(ip, p.targetBitPosition(), p.numBitsHandled)
}

func (p *PrefixTrie) level() int {
	if p.parent == nil {
		return 0
	}
	return p.parent.level() + 1
}

// walkDepth walks the trie in depth order, for unit testing.
func (p *PrefixTrie) walkDepth() <-chan net.IPNet {
	networks := make(chan net.IPNet)
	go func() {
		if p.hasEntry {
			networks <- *p.network
		}
		subNetworks := []<-chan net.IPNet{}
		for _, trie := range p.children {
			if trie == nil {
				continue
			}
			subNetworks = append(subNetworks, trie.walkDepth())
		}
		for _, subNetwork := range subNetworks {
			for network := range subNetwork {
				networks <- network
			}
		}
		close(networks)
	}()
	return networks
}
