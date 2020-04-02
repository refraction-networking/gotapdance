package phantoms

import (
	"encoding/hex"
	"math/rand"
	"net"
	"testing"
)

func TestIPSelectionAlt(t *testing.T) {

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	if err != nil {
		t.Fatalf("Issue decoding seedStr")
	}

	//netStr := "192.122.190.0/24"
	netStr := "2001:48a8:687f:1::/64"
	_, net1, err := net.ParseCIDR(netStr)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := SelectAddrFromSubnet(seed, net1)
	if err != nil {
		t.Fatal(err)
	} else if addr.String() != "2001:48a8:687f:1:5fa4:c34c:434e:ddd" {
		t.Fatalf("Wrong Address Selected: %v -> expected (%v)", addr, "2001:48a8:687f:1:5fa4:c34c:434e:ddd")
	}

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

	var ps = SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"192.122.190.0/24"}},
			{Weight: 1, Subnets: []string{"141.219.0.0/16"}},
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
			t.Fatalf("failed to parse SubnetConfig: %v, %v, %v", seed, true, ps)
		}
	}
	t.Logf("%.2f%%, %.2f%%", float32(count[0])/float32(loops)*100.0, float32(count[1])/float32(loops)*100.0)
}

func TestWeightedSelection(t *testing.T) {

	count := []int{0, 0}
	loops := 1000
	rand.Seed(5421212341231)

	var ps = SubnetConfig{
		WeightedSubnets: []ConjurePhantomSubnet{
			{Weight: 9, Subnets: []string{"1"}},
			{Weight: 1, Subnets: []string{"2"}},
		},
	}

	for i := 1; i <= loops; i++ {
		seed := make([]byte, 16)
		_, err := rand.Read(seed)
		if err != nil {
			t.Fatalf("Failed to generate seed: %v", err)
		}

		sa := ps.getSubnets(seed, true)
		if sa == nil {
			t.Fatalf("failed to parse SubnetConfig: %v, %v, %v", seed, true, ps)

		} else if sa[0] == "1" {
			count[0]++
		} else if sa[0] == "2" {
			count[1]++
		}

	}
	t.Logf("%.2f%%, %.2f%%", float32(count[0])/float32(loops)*100.0, float32(count[1])/float32(loops)*100.0)
}

var phantomSubnets = SubnetConfig{
	WeightedSubnets: []ConjurePhantomSubnet{
		{Weight: 9, Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}},
		{Weight: 1, Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"}},
	},
}

func TestSelectFilter(t *testing.T) {
	seed, err := hex.DecodeString("5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	if err != nil {
		t.Fatalf("Issue decoding seedStr")
	}

	p, err := SelectPhantomWeighted([]byte(seed), phantomSubnets, V4Only)
	if err != nil {
		t.Fatalf("Failed to select phantom: %v", err)
	}
	t.Logf("%v\n", p)

	p, err = SelectPhantomWeighted([]byte(seed), phantomSubnets, V6Only)
	if err != nil {
		t.Fatalf("Failed to select phantom: %v", err)
	}
	t.Logf("%v\n", p)

	p, err = SelectPhantomWeighted([]byte(seed), phantomSubnets, nil)
	if err != nil {
		t.Fatalf("Failed to select phantom: %v", err)
	}
	t.Logf("%v\n", p)
}
