package cidranger

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	rnet "github.com/yl2chen/cidranger/net"
)

/*
 ******************************************************************
 Test Contains/ContainingNetworks against basic brute force ranger.
 ******************************************************************
*/

func TestContainsAgainstBaseIPv4(t *testing.T) {
	testContainsAgainstBase(t, 100000, randIPv4Gen)
}

func TestContainingNetworksAgaistBaseIPv4(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, randIPv4Gen)
}

func TestCoveredNetworksAgainstBaseIPv4(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV4AWSRangesIPNets))
}

// IPv6 spans an extremely large address space (2^128), randomly generated IPs
// will often fall outside of the test ranges (AWS public CIDR blocks), so it
// it more meaningful for testing to run from a curated list of IPv6 IPs.
func TestContainsAgaistBaseIPv6(t *testing.T) {
	testContainsAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestContainingNetworksAgaistBaseIPv6(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestCoveredNetworksAgainstBaseIPv6(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV6AWSRangesIPNets))
}

func testContainsAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		expected, err := baseRanger.Contains(nn.ToIP())
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.Contains(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		}
	}
}

func testContainingNetworksAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		expected, err := baseRanger.ContainingNetworks(nn.ToIP())
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.ContainingNetworks(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

func testCoversNetworksAgainstBase(t *testing.T, iterations int, netGen networkGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < iterations; i++ {
		network := netGen()
		expected, err := baseRanger.CoveredNetworks(network.IPNet)
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.CoveredNetworks(network.IPNet)
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

/*
 ******************************************************************
 Benchmarks.
 ******************************************************************
*/

func BenchmarkPCTrieHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), newBruteRanger())
}

func BenchmarkPCTrieHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), newBruteRanger())
}

func BenchmarkPCTrieMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), newBruteRanger())
}

func BenchmarkPCTrieHMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), newBruteRanger())
}

func BenchmarkPCTrieHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("52.95.110.1"), newBruteRanger())
}

func BenchmarkPCTrieHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), newBruteRanger())
}

func BenchmarkPCTrieMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("123.123.123.123"), newBruteRanger())
}

func BenchmarkPCTrieHMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620::ffff"), newBruteRanger())
}

func benchmarkContainsUsingAWSRanges(tb testing.TB, nn net.IP, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.Contains(nn)
	}
}

func benchmarkContainingNetworksUsingAWSRanges(tb testing.TB, nn net.IP, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.ContainingNetworks(nn)
	}
}

/*
 ******************************************************************
 Helper methods and initialization.
 ******************************************************************
*/

type ipGenerator func() rnet.NetworkNumber

func randIPv4Gen() rnet.NetworkNumber {
	return rnet.NetworkNumber{rand.Uint32()}
}
func randIPv6Gen() rnet.NetworkNumber {
	return rnet.NetworkNumber{rand.Uint32(), rand.Uint32(), rand.Uint32(), rand.Uint32()}
}
func curatedAWSIPv6Gen() rnet.NetworkNumber {
	randIdx := rand.Intn(len(ipV6AWSRangesIPNets))

	// Randomly generate an IP somewhat near the range.
	network := ipV6AWSRangesIPNets[randIdx]
	nn := rnet.NewNetworkNumber(network.IP)
	ones, bits := network.Mask.Size()
	zeros := bits - ones
	nnPartIdx := zeros / rnet.BitsPerUint32
	nn[nnPartIdx] = rand.Uint32()
	return nn
}

type networkGenerator func() rnet.Network

func randomIPNetGenFactory(pool []*net.IPNet) networkGenerator {
	return func() rnet.Network {
		return rnet.NewNetwork(*pool[rand.Intn(len(pool))])
	}
}

type AWSRanges struct {
	Prefixes     []Prefix     `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type IPv6Prefix struct {
	IPPrefix string `json:"ipv6_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

var awsRanges *AWSRanges
var ipV4AWSRangesIPNets []*net.IPNet
var ipV6AWSRangesIPNets []*net.IPNet

func loadAWSRanges() *AWSRanges {
	file, err := ioutil.ReadFile("./testdata/aws_ip_ranges.json")
	if err != nil {
		panic(err)
	}
	var ranges AWSRanges
	err = json.Unmarshal(file, &ranges)
	if err != nil {
		panic(err)
	}
	return &ranges
}

func configureRangerWithAWSRanges(tb testing.TB, ranger Ranger) {
	for _, prefix := range awsRanges.Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(NewBasicRangerEntry(*network))
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(NewBasicRangerEntry(*network))
	}
}

func init() {
	awsRanges = loadAWSRanges()
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV6AWSRangesIPNets = append(ipV6AWSRangesIPNets, network)
	}
	for _, prefix := range awsRanges.Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV4AWSRangesIPNets = append(ipV4AWSRangesIPNets, network)
	}
	rand.Seed(time.Now().Unix())
}
