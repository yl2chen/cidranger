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

func BenchmarkLPCTrieUsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, NewLPCTrieRanger())
}

func BenchmarkBruteRangerUsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, NewBruteRanger())
}

func configureRangerWithAWSRanges(tb testing.TB, ranger Ranger) {
	ranges := loadAWSRanges(tb)
	for _, prefix := range ranges.Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(*network)
	}
}

func benchmarkContainsUsingAWSRanges(tb testing.TB, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	ip := net.ParseIP("52.95.110.1")
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.Contains(ip)
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
