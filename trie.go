package cidranger

import (
	"fmt"
	"net"
	"strings"

	rnet "github.com/yl2chen/cidranger/net"
)

// prefixTrie is a path-compressed (PC) trie implementation of the
// ranger interface inspired by this blog post:
// https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux
//
// CIDR blocks are stored using a prefix tree structure where each node has its
// parent as prefix, and the path from the root node represents current CIDR
// block.
//
// For IPv4, the trie structure guarantees max depth of 32 as IPv4 addresses are
// 32 bits long and each bit represents a prefix tree starting at that bit. This
// property also guarantees constant lookup time in Big-O notation.
//
// Path compression compresses a string of node with only 1 child into a single
// node, decrease the amount of lookups necessary during containment tests.
//
// Level compression dictates the amount of direct children of a node by
// allowing it to handle multiple bits in the path.  The heuristic (based on
// children population) to decide when the compression and decompression happens
// is outlined in the prior linked blog, and will be experimented with in more
// depth in this project in the future.
//
// Note: Can not insert both IPv4 and IPv6 network addresses into the same
// prefix trie, use versionedRanger wrapper instead.
//
// TODO: Implement level-compressed component of the LPC trie.
type prefixTrie[V any] struct {
	parent   *prefixTrie[V]
	children []*prefixTrie[V]

	numBitsSkipped uint
	numBitsHandled uint

	network rnet.Network
	entry   RangerEntry
	value   V

	size int // This is only maintained in the root trie.
}

// newPrefixTree creates a new prefixTrie.
func newPrefixTree[V any](version rnet.IPVersion, defaultValue ...V) Ranger[V] {
	_, rootNet, _ := net.ParseCIDR("0.0.0.0/0")
	if version == rnet.IPv6 {
		_, rootNet, _ = net.ParseCIDR("0::0/0")
	}

	var value V
	if len(defaultValue) > 0 {
		value = defaultValue[0]
	}
	return &prefixTrie[V]{
		children:       make([]*prefixTrie[V], 2, 2),
		numBitsSkipped: 0,
		numBitsHandled: 1,
		network:        rnet.NewNetwork(*rootNet),
		value:          value,
	}
}

func newPathprefixTrie[V any](network rnet.Network, numBitsSkipped uint, value V) *prefixTrie[V] {
	path := &prefixTrie[V]{
		children:       make([]*prefixTrie[V], 2, 2),
		numBitsSkipped: numBitsSkipped,
		numBitsHandled: 1,
		network:        network.Masked(int(numBitsSkipped)),
		value:          value,
	}
	return path
}

func newEntryTrie[V any](network rnet.Network, entry RangerEntry, value V) *prefixTrie[V] {
	ones, _ := network.IPNet.Mask.Size()
	leaf := newPathprefixTrie(network, uint(ones), value)
	leaf.entry = entry
	return leaf
}

// Insert inserts a RangerEntry into prefix trie.
func (p *prefixTrie[V]) Insert(entry RangerEntry, value ...V) error {
	network := entry.Network()
	var val V
	if len(value) > 0 {
		val = value[0]
	}
	sizeIncreased, err := p.insert(rnet.NewNetwork(network), entry, val)
	if sizeIncreased {
		p.size++
	}
	return err
}

// Remove removes RangerEntry identified by given network from trie.
func (p *prefixTrie[V]) Remove(network net.IPNet) (RangerEntry, error) {
	entry, err := p.remove(rnet.NewNetwork(network))
	if entry != nil {
		p.size--
	}
	return entry, err
}

// Contains returns boolean indicating whether given ip is contained in any
// of the inserted networks.
func (p *prefixTrie[V]) Contains(ip net.IP) (bool, error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return false, ErrInvalidNetworkNumberInput
	}
	return p.contains(nn)
}

// ContainingNetworks returns the list of RangerEntry(s) the given ip is
// contained in in ascending prefix order.
func (p *prefixTrie[V]) ContainingNetworks(ip net.IP) ([]RangerEntry, error) {
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return nil, ErrInvalidNetworkNumberInput
	}
	return p.containingNetworks(nn)
}

// IterByIncomingNetworks iterates over all networks that the transmitted IP is included in.
func (p *prefixTrie[V]) IterByIncomingNetworks(ip net.IP, f func(network net.IPNet, value V) error) error {
	if err := f(p.network.IPNet, p.value); err != nil {
		return err
	}
	nn := rnet.NewNetworkNumber(ip)
	if nn == nil {
		return ErrInvalidNetworkNumberInput
	}
	return p.iterByIncomingNetworks(nn, f)
}

// CoveredNetworks returns the list of RangerEntry(s) the given ipnet
// covers.  That is, the networks that are completely subsumed by the
// specified network.
func (p *prefixTrie[V]) CoveredNetworks(network net.IPNet) ([]RangerEntry, error) {
	net := rnet.NewNetwork(network)
	return p.coveredNetworks(net)
}

// Len returns number of networks in ranger.
func (p *prefixTrie[V]) Len() int {
	return p.size
}

// String returns string representation of trie, mainly for visualization and
// debugging.
func (p *prefixTrie[V]) String() string {
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
		p.targetBitPosition(), p.hasEntry(), strings.Join(children, ""))
}

func (p *prefixTrie[V]) contains(number rnet.NetworkNumber) (bool, error) {
	if !p.network.Contains(number) {
		return false, nil
	}
	if p.hasEntry() {
		return true, nil
	}
	if p.targetBitPosition() < 0 {
		return false, nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return false, err
	}
	child := p.children[bit]
	if child != nil {
		return child.contains(number)
	}
	return false, nil
}

func (p *prefixTrie[V]) containingNetworks(number rnet.NetworkNumber) ([]RangerEntry, error) {
	results := []RangerEntry{}
	if !p.network.Contains(number) {
		return results, nil
	}
	if p.hasEntry() {
		results = []RangerEntry{p.entry}
	}
	if p.targetBitPosition() < 0 {
		return results, nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return nil, err
	}
	child := p.children[bit]
	if child != nil {
		ranges, err := child.containingNetworks(number)
		if err != nil {
			return nil, err
		}
		if len(ranges) > 0 {
			if len(results) > 0 {
				results = append(results, ranges...)
			} else {
				results = ranges
			}
		}
	}
	return results, nil
}

func (p *prefixTrie[V]) iterByIncomingNetworks(number rnet.NetworkNumber,
	f func(network net.IPNet, value V) error) error {
	if !p.network.Contains(number) {
		return nil
	}

	if p.hasEntry() {
		if err := f(p.network.IPNet, p.value); err != nil {
			return err
		}
	}
	if p.targetBitPosition() < 0 {
		return nil
	}
	bit, err := p.targetBitFromIP(number)
	if err != nil {
		return err
	}
	child := p.children[bit]
	if child != nil {
		err = child.iterByIncomingNetworks(number, f)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *prefixTrie[V]) coveredNetworks(network rnet.Network) ([]RangerEntry, error) {
	var results []RangerEntry
	if network.Covers(p.network) {
		for entry := range p.walkDepth() {
			results = append(results, entry)
		}
	} else if p.targetBitPosition() >= 0 {
		bit, err := p.targetBitFromIP(network.Number)
		if err != nil {
			return results, err
		}
		child := p.children[bit]
		if child != nil {
			return child.coveredNetworks(network)
		}
	}
	return results, nil
}

func (p *prefixTrie[V]) insert(network rnet.Network, entry RangerEntry, value V) (bool, error) {
	if p.network.Equal(network) {
		sizeIncreased := p.entry == nil
		p.entry = entry
		return sizeIncreased, nil
	}

	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return false, err
	}
	existingChild := p.children[bit]

	// No existing child, insert new leaf trie.
	if existingChild == nil {
		p.appendTrie(bit, newEntryTrie(network, entry, value))
		return true, nil
	}

	// Check whether it is necessary to insert additional path prefix between current trie and existing child,
	// in the case that inserted network diverges on its path to existing child.
	lcb, err := network.LeastCommonBitPosition(existingChild.network)
	divergingBitPos := int(lcb) - 1
	if divergingBitPos > existingChild.targetBitPosition() {
		pathPrefix := newPathprefixTrie(network, p.totalNumberOfBits()-lcb, value)
		err := p.insertPrefix(bit, pathPrefix, existingChild)
		if err != nil {
			return false, err
		}
		// Update new child
		existingChild = pathPrefix
	}
	return existingChild.insert(network, entry, value)
}

func (p *prefixTrie[V]) appendTrie(bit uint32, prefix *prefixTrie[V]) {
	p.children[bit] = prefix
	prefix.parent = p
}

func (p *prefixTrie[V]) insertPrefix(bit uint32, pathPrefix, child *prefixTrie[V]) error {
	// Set parent/child relationship between current trie and inserted pathPrefix
	p.children[bit] = pathPrefix
	pathPrefix.parent = p

	// Set parent/child relationship between inserted pathPrefix and original child
	pathPrefixBit, err := pathPrefix.targetBitFromIP(child.network.Number)
	if err != nil {
		return err
	}
	pathPrefix.children[pathPrefixBit] = child
	child.parent = pathPrefix
	return nil
}

func (p *prefixTrie[V]) remove(network rnet.Network) (RangerEntry, error) {
	if p.hasEntry() && p.network.Equal(network) {
		entry := p.entry
		p.entry = nil

		err := p.compressPathIfPossible()
		if err != nil {
			return nil, err
		}
		return entry, nil
	}
	if p.targetBitPosition() < 0 {
		return nil, nil
	}
	bit, err := p.targetBitFromIP(network.Number)
	if err != nil {
		return nil, err
	}
	child := p.children[bit]
	if child != nil {
		return child.remove(network)
	}
	return nil, nil
}

func (p *prefixTrie[V]) qualifiesForPathCompression() bool {
	// Current prefix trie can be path compressed if it meets all following.
	//		1. records no CIDR entry
	//		2. has single or no child
	//		3. is not root trie
	return !p.hasEntry() && p.childrenCount() <= 1 && p.parent != nil
}

func (p *prefixTrie[V]) compressPathIfPossible() error {
	if !p.qualifiesForPathCompression() {
		// Does not qualify to be compressed
		return nil
	}

	// Find lone child.
	var loneChild *prefixTrie[V]
	for _, child := range p.children {
		if child != nil {
			loneChild = child
			break
		}
	}

	// Find root of currnt single child lineage.
	parent := p.parent
	for ; parent.qualifiesForPathCompression(); parent = parent.parent {
	}
	parentBit, err := parent.targetBitFromIP(p.network.Number)
	if err != nil {
		return err
	}
	parent.children[parentBit] = loneChild

	// Attempts to furthur apply path compression at current lineage parent, in case current lineage
	// compressed into parent.
	return parent.compressPathIfPossible()
}

func (p *prefixTrie[V]) childrenCount() int {
	count := 0
	for _, child := range p.children {
		if child != nil {
			count++
		}
	}
	return count
}

func (p *prefixTrie[V]) totalNumberOfBits() uint {
	return rnet.BitsPerUint32 * uint(len(p.network.Number))
}

func (p *prefixTrie[V]) targetBitPosition() int {
	return int(p.totalNumberOfBits()-p.numBitsSkipped) - 1
}

func (p *prefixTrie[V]) targetBitFromIP(n rnet.NetworkNumber) (uint32, error) {
	// This is a safe uint boxing of int since we should never attempt to get
	// target bit at a negative position.
	return n.Bit(uint(p.targetBitPosition()))
}

func (p *prefixTrie[V]) hasEntry() bool {
	return p.entry != nil
}

func (p *prefixTrie[V]) level() int {
	if p.parent == nil {
		return 0
	}
	return p.parent.level() + 1
}

// walkDepth walks the trie in depth order, for unit testing.
func (p *prefixTrie[V]) walkDepth() <-chan RangerEntry {
	entries := make(chan RangerEntry)
	go func() {
		if p.hasEntry() {
			entries <- p.entry
		}
		childEntriesList := []<-chan RangerEntry{}
		for _, trie := range p.children {
			if trie == nil {
				continue
			}
			childEntriesList = append(childEntriesList, trie.walkDepth())
		}
		for _, childEntries := range childEntriesList {
			for entry := range childEntries {
				entries <- entry
			}
		}
		close(entries)
	}()
	return entries
}
