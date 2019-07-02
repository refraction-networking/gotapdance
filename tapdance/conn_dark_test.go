package tapdance

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSelectIpv4(t *testing.T) {
	fmt.Print("\nTesting IPv4 only' selection:\n")

	_ddIpSelector, err := newDDIpSelector([]string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}, false)
	if err != nil {
		t.Error("Failed IP selector initialization ", err)
	}

	fmt.Println("\nAvailable network blocks:")
	for _, _net := range _ddIpSelector.nets {
		fmt.Println(_net)
		if _net.IP.To4() == nil {
			t.Error("Encountered Non IPv4 Network block")
			t.FailNow()
		}
	}

	seed := make([]byte, 16)
	_, err = rand.Read(seed)
	if err != nil {
		t.Errorf("Crypto/Rand error -- %s\n", err)
		t.FailNow()
	}

	darDecoyIpAddr, err := _ddIpSelector.selectIpAddr(seed)
	if err != nil {
		t.Errorf("Error selecting decoy address -- %s\n", err)
		t.FailNow()
	}
	if darDecoyIpAddr.To4() == nil {
		t.Error("No IPv4 address Selected")
	}
	fmt.Println("\nRandomly chosen address: ", darDecoyIpAddr)
}

func TestSelectIpv6(t *testing.T) {
	fmt.Print("\nTesting Ipv6 support (v4 and v6 selection):\n")

	_ddIpSelector, err := newDDIpSelector([]string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}, true)
	if err != nil {
		t.Error("Failed IP selector initialization ", err)
	}

	fmt.Println("\nAvailable network blocks:")
	for _, _net := range _ddIpSelector.nets {
		fmt.Println(_net)
		if _net.IP.To16() == nil && _net.IP.To4() == nil {
			t.Error("Encountered Unknown Network block")
			t.FailNow()
		}
	}

	seed := make([]byte, 16)
	_, err = rand.Read(seed)
	if err != nil {
		t.Errorf("Crypto/Rand error -- %s\n", err)
		t.FailNow()
	}

	darDecoyIpAddr, err := _ddIpSelector.selectIpAddr(seed)
	if err != nil {
		t.Errorf("Error selecting decoy address -- %s\n", err)
		t.FailNow()
	}

	fmt.Println("\nRandomly chosen address: ", darDecoyIpAddr)
}
