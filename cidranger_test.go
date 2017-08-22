package cidranger

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yl2chen/cidranger/util/ip"
)

type AWSRanges struct {
	Prefixes []Prefix `json:"prefixes"`
}

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

func TestContains(t *testing.T) {
	rangers := []Ranger{NewLPCTrieRanger()}
	groundRanger := NewBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, groundRanger)

	for i := 0; i < 100000; i++ {
		nn := ip.Uint32ToIPv4(rand.Uint32())
		expected, err := groundRanger.Contains(nn)
		for _, ranger := range rangers {
			assert.NoError(t, err)
			actual, err := ranger.Contains(nn)
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		}
	}
}

func TestContainingNetworks(t *testing.T) {
	rangers := []Ranger{NewLPCTrieRanger()}
	groundRanger := NewBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, groundRanger)

	for i := 0; i < 100000; i++ {
		nn := ip.Uint32ToIPv4(rand.Uint32())
		expected, err := groundRanger.ContainingNetworks(nn)
		for _, ranger := range rangers {
			assert.NoError(t, err)
			actual, err := ranger.ContainingNetworks(nn)
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

/*
 *********************************
 Benchmarking
 *********************************
*/

func BenchmarkIPv4ToUint32(b *testing.B) {
	nn := net.ParseIP("52.95.110.1")
	for n := 0; n < b.N; n++ {
		ip.IPv4ToUint32(nn)
	}
}

func BenchmarkUint32ToIPv4(b *testing.B) {
	for n := 0; n < b.N; n++ {
		ip.Uint32ToIPv4(878669313)
	}
}

func BenchmarkExtractBits(b *testing.B) {
	nn := net.ParseIP("52.95.110.1")
	ipUint32, _ := ip.IPv4ToUint32(nn)
	for n := 0; n < b.N; n++ {
		ip.IPv4BitsAsUint(ipUint32, 6, 1)
	}
}

func BenchmarkLPCTrieHitUsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewLPCTrieRanger())
}

func BenchmarkBruteRangerHitUsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewBruteRanger())
}

func BenchmarkLPCTrieMissUsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewLPCTrieRanger())
}

func BenchmarkBruteRangerMissUsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewBruteRanger())
}

func configureRangerWithAWSRanges(tb testing.TB, ranger Ranger) {
	ranges := loadAWSRanges(tb)
	for _, prefix := range ranges.Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(*network)
	}
}

func benchmarkContainsUsingAWSRanges(tb testing.TB, nn net.IP, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.Contains(nn)
	}
}

func loadAWSRanges(tb testing.TB) *AWSRanges {
	file, err := ioutil.ReadFile("./testdata/aws_ip_ranges.json")
	assert.NoError(tb, err)

	var ranges AWSRanges
	err = json.Unmarshal(file, &ranges)
	assert.NoError(tb, err)
	return &ranges
}
