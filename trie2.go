package cidranger

import (
	"net"

	rnet "github.com/libp2p/go-cidranger/net"
	t2 "github.com/libp2p/go-libp2p-xor/trie2"
)

type cidrEntry struct {
	net.IPNet
}

func (e cidrEntry) Network() net.IPNet {
	return e.IPNet
}

type rangerKey struct {
	IP    net.IP
	Size  int
	Entry RangerEntry
}

func rangerEntryToKey(e RangerEntry) rangerKey {
	s, _ := e.Network().Mask.Size()
	return rangerKey{IP: e.Network().IP, Size: s, Entry: e}
}

func ipToKey(ip net.IP) rangerKey {
	return rangerKey{IP: ip, Size: len(ip) * 8}
}

func (k rangerKey) Equal(r t2.Key) bool {
	if k2, ok := r.(rangerKey); ok {
		if k.Len() != k2.Len() {
			return false
		} else {
			return commonPrefixLen(k.IP, k2.IP) == k.Len()
		}
	} else {
		return false
	}
}

// This function is taken from Go: https://golang.org/src/net/addrselect.go?s=9240:9279#L345
//
// commonPrefixLen reports the length of the longest prefix (looking
// at the most significant, or leftmost, bits) that the
// two addresses have in common, up to the length of a's prefix (i.e.,
// the portion of the address not including the interface ID).
//
// If a or b is an IPv4 address as an IPv6 address, the IPv4 addresses
// are compared (with max common prefix length of 32).
// If a and b are different IP versions, 0 is returned.
//
// See https://tools.ietf.org/html/rfc6724#section-2.2
func commonPrefixLen(a, b net.IP) (cpl int) {
	if a4 := a.To4(); a4 != nil {
		a = a4
	}
	if b4 := b.To4(); b4 != nil {
		b = b4
	}
	if len(a) != len(b) {
		return 0
	}
	// If IPv6, only up to the prefix (first 64 bits)
	if len(a) > 8 {
		a = a[:8]
		b = b[:8]
	}
	for len(a) > 0 {
		if a[0] == b[0] {
			cpl += 8
			a = a[1:]
			b = b[1:]
			continue
		}
		bits := 8
		ab, bb := a[0], b[0]
		for {
			ab >>= 1
			bb >>= 1
			bits--
			if ab == bb {
				cpl += bits
				return
			}
		}
	}
	return
}

func (k rangerKey) BitAt(i int) byte {
	b := []byte(k.IP)
	// the most significant byte in an IP address is the first one
	d := b[i/8] & (byte(1) << (i % 8))
	if d == 0 {
		return 0
	} else {
		return 1
	}
}

func (k rangerKey) Len() int {
	return k.Size
}

type trie2Ranger struct {
	trie *t2.Trie
}

func newTrie2Ranger(v rnet.IPVersion) Ranger {
	// XXX: do we need to pre-add rootnet 0.0.0.0/0 and for ipv6
	return &trie2Ranger{trie: &t2.Trie{}}
}

func (r *trie2Ranger) Insert(entry RangerEntry) error {
	r.trie.Add(rangerEntryToKey(entry))
	return nil
}

func (r *trie2Ranger) Remove(network net.IPNet) (RangerEntry, error) {
	panic("not supported")
}

func (r *trie2Ranger) Contains(ip net.IP) (bool, error) {
	if c, err := r.ContainingNetworks(ip); err != nil {
		return false, err
	} else {
		return len(c) > 0, nil
	}
}

func (r *trie2Ranger) ContainingNetworks(ip net.IP) ([]RangerEntry, error) {
	_, found := r.trie.FindSubKeys(ipToKey(ip))
	q := make([]RangerEntry, len(found))
	for i, f := range found {
		q[i] = f.(rangerKey).Entry
	}
	return q, nil
}

func (r *trie2Ranger) CoveredNetworks(network net.IPNet) ([]RangerEntry, error) {
	panic("not supported")
}

func (r *trie2Ranger) Len() int {
	return r.trie.Size()
}
