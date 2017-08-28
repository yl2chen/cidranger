package cidranger

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	rnet "github.com/yl2chen/cidranger/net"
)

type AWSRanges struct {
	Prefixes []Prefix `json:"prefixes"`
}

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

/*
 ******************************************************************
 Test Contains/ContainingNetworks against basic brute force ranger.
 ******************************************************************
*/

func TestContainsAgainstBase(t *testing.T) {
	rangers := []Ranger{NewLPCTrieRanger()}
	baseRanger := NewBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < 100000; i++ {
		nn := rnet.NetworkNumber{rand.Uint32()}
		expected, err := baseRanger.Contains(nn.ToIP())
		for _, ranger := range rangers {
			assert.NoError(t, err)
			actual, err := ranger.Contains(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		}
	}
}

func TestContainingNetworksAgainstBase(t *testing.T) {
	rangers := []Ranger{NewLPCTrieRanger()}
	baseRanger := NewBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < 100000; i++ {
		nn := rnet.NetworkNumber{rand.Uint32()}
		expected, err := baseRanger.ContainingNetworks(nn.ToIP())
		for _, ranger := range rangers {
			assert.NoError(t, err)
			actual, err := ranger.ContainingNetworks(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
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
