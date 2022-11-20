package phantoms

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestIPSelectionBasic(t *testing.T) {

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	netStr := "2001:48a8:687f:1::/64"
	_, net1, err := net.ParseCIDR(netStr)
	require.Nil(t, err)

	addr, err := SelectAddrFromSubnet(seed, net1)
	require.Nil(t, err)
	require.Equal(t, "2001:48a8:687f:1:5fa4:c34c:434e:ddd", addr.String())
}

func TestSelectWeightedMany(t *testing.T) {

	count := []int{0, 0}
	loops := 1000
	rand.Seed(12345)
	_, net1, err := net.ParseCIDR("192.122.190.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, net2, err := net.ParseCIDR("141.219.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	var ps = &pb.PhantomSubnetsList{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: &w1, Subnets: []string{"192.122.190.0/24"}},
			{Weight: &w9, Subnets: []string{"141.219.0.0/16"}},
		},
	}

	for i := 1; i <= loops; i++ {
		seed := make([]byte, 16)
		_, err := rand.Read(seed)
		if err != nil {
			t.Fatalf("Failed to generate seed: %v", err)
		}

		addr, err := SelectPhantom(seed, ps, nil, true)
		if err != nil {
			t.Fatalf("Failed to select adddress: %v -- %s, %v, %v, %v -- %v", err, hex.EncodeToString(seed), ps, "None", true, count)
		}

		if net1.Contains(*addr) {
			count[0]++
		} else if net2.Contains(*addr) {
			count[1]++
		} else {
			t.Fatalf("failed to parse pb.PhantomSubnetsList: %v, %v, %v", seed, true, ps)
		}
	}
	t.Logf("%.2f%%, %.2f%%", float32(count[0])/float32(loops)*100.0, float32(count[1])/float32(loops)*100.0)
}

func TestWeightedSelection(t *testing.T) {

	count := []int{0, 0}
	loops := 1000
	rand.Seed(5421212341231)
	w := uint32(1)
	var ps = &pb.PhantomSubnetsList{
		WeightedSubnets: []*pb.PhantomSubnets{
			{Weight: &w, Subnets: []string{"1"}},
			{Weight: &w, Subnets: []string{"2"}},
		},
	}

	for i := 1; i <= loops; i++ {
		seed := make([]byte, 16)
		_, err := rand.Read(seed)
		if err != nil {
			t.Fatalf("Failed to generate seed: %v", err)
		}

		sa := getSubnets(ps, seed, true)
		if sa == nil {
			t.Fatalf("failed to parse pb.PhantomSubnetsList: %v, %v, %v", seed, true, ps)

		} else if sa[0] == "1" {
			count[0]++
		} else if sa[0] == "2" {
			count[1]++
		}

	}
	t.Logf("%.2f%%, %.2f%%", float32(count[0])/float32(loops)*100.0, float32(count[1])/float32(loops)*100.0)
}

var w1 = uint32(1)
var w9 = uint32(9)
var phantomSubnets = &pb.PhantomSubnetsList{
	WeightedSubnets: []*pb.PhantomSubnets{
		{Weight: &w9, Subnets: []string{"192.122.190.0/24", "10.0.0.0/31", "2001:48a8:687f:1::/64"}},
		{Weight: &w1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
	},
}

func TestSelectFilter(t *testing.T) {
	seed, err := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	p, err := SelectPhantomWeighted([]byte(seed), phantomSubnets, V4Only)
	require.Nil(t, err)
	require.Equal(t, "192.122.190.130", p.String())

	p, err = SelectPhantomWeighted([]byte(seed), phantomSubnets, V6Only)
	require.Nil(t, err)
	require.Equal(t, "2001:48a8:687f:1:5fa4:c34c:434e:ddd", p.String())

	p, err = SelectPhantomWeighted([]byte(seed), phantomSubnets, nil)
	require.Nil(t, err)
	require.Equal(t, "2001:48a8:687f:1:5fa4:c34c:434e:ddd", p.String())
}

func TestPhantomsV6OnlyFilter(t *testing.T) {
	testNets := []string{"192.122.190.0/24", "2001:48a8:687f:1::/64", "2001:48a8:687f:1::/64"}
	testNetsParsed, err := parseSubnets(testNets)
	require.Nil(t, err)
	require.Equal(t, 3, len(testNetsParsed))

	testNetsParsed, err = V6Only(testNetsParsed)
	require.Nil(t, err)
	require.Equal(t, 2, len(testNetsParsed))
}

// TestPhantomsSeededSelectionV4Min ensures that minimal subnets work because
// they re useful to test limitations (i.e. multiple clients sharing a phantom
// address)
func TestPhantomsSeededSelectionV4Min(t *testing.T) {
	subnets, err := parseSubnets([]string{"192.122.190.0/32", "2001:48a8:687f:1::/128"})
	require.Nil(t, err)

	seed, err := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	phantomAddr, err := selectIPAddr(seed, subnets)
	require.Nil(t, err)

	possibleAddrs := []string{"192.122.190.0", "2001:48a8:687f:1::"}
	require.Contains(t, possibleAddrs, phantomAddr.String())
}

// TestPhantomSeededSelectionFuzz ensures that all phantom subnet sizes are
// viable including small (/31, /32, etc.) subnets which were previously
// experiencing a divide by 0.
func TestPhantomSeededSelectionFuzz(t *testing.T) {
	_, defaultV6, err := net.ParseCIDR("2001:48a8:687f:1::/64")
	require.Nil(t, err)

	var randSeed int64 = 1234
	r := rand.New(rand.NewSource(randSeed))

	// Add generation with only one v4 subnet that has a varying mask len
	for i := 0; i <= 32; i++ {
		s := "255.255.255.255/" + fmt.Sprint(i)
		_, variableSubnet, err := net.ParseCIDR(s)
		require.Nil(t, err)

		subnets := []*net.IPNet{defaultV6, variableSubnet}

		var seed = make([]byte, 32)
		for j := 0; j < 10000; j++ {
			n, err := r.Read(seed)
			require.Nil(t, err)
			require.Equal(t, n, 32)

			// phantomAddr, err := phantomSelector.Select(seed, newGen, false)
			phantomAddr, err := selectIPAddr(seed, subnets)
			require.Nil(t, err, "i=%d, j=%d, seed='%s'", i, j, hex.EncodeToString(seed))
			require.NotNil(t, phantomAddr)
		}
	}
}

func ExpandSeed(seed, salt []byte, i int) []byte {
	bi := make([]byte, 8)
	binary.LittleEndian.PutUint64(bi, uint64(i))
	return hkdf.Extract(sha256.New, seed, append(salt, bi...))
}

func parseClientConf(fname string) (*pb.ClientConf, error) {

	clientConf := &pb.ClientConf{}
	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(buf, clientConf)
	if err != nil {
		return nil, err
	}
	return clientConf, nil
}

func TestBias(t *testing.T) {
	seed, _ := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	salt := []byte("phantom-bias-test")

	clientConf, err := parseClientConf("./ClientConf")
	require.Nil(t, err)
	ps := clientConf.GetPhantomSubnetsList()
	ipCount := map[string]int{}

	//snets, err := parseSubnets(getSubnets(ps, nil, true))
	//require.Nil(t, err)
	//for snet := range snets {
	//}
	totTrials := 1000000
	for i := 0; i < totTrials; i++ {
		curSeed := ExpandSeed(seed, salt, i)
		addr, err := SelectPhantom(curSeed, ps, V4Only, true)
		//addr, err := SelectPhantom(curSeed, ps, nil, true)
		require.Nil(t, err)
		ipCount[addr.String()] += 1
	}
	// Write file
	f, err := os.Create("./bias-ips.out")
	require.Nil(t, err)
	defer f.Close()

	for ip, count := range ipCount {
		f.WriteString(fmt.Sprintf("%s %d\n", ip, count))
	}
}
