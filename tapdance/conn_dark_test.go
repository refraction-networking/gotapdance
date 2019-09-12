package tapdance

import (
	"crypto/rand"
	"testing"
)

func TestSelectIpv4(t *testing.T) {

	_ddIPSelector, err := newDDIpSelector([]string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}, false)
	if err != nil {
		t.Fatal("Failed IP selector initialization ", err)
	}

	for _, _net := range _ddIPSelector.nets {
		if _net.IP.To4() == nil {
			t.Fatal("Encountered Non IPv4 Network block")
		}
	}

	seed := make([]byte, 16)
	_, err = rand.Read(seed)
	if err != nil {
		t.Fatalf("Crypto/Rand error -- %s\n", err)
	}

	darDecoyIPAddr, err := _ddIPSelector.selectIpAddr(seed)
	if err != nil {
		t.Fatalf("Error selecting decoy address -- %s\n", err)
	}
	if darDecoyIPAddr.To4() == nil {
		t.Fatal("No IPv4 address Selected")
	}
}

func TestSelectIpv6(t *testing.T) {

	_ddIPSelector, err := newDDIpSelector([]string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}, true)
	if err != nil {
		t.Fatal("Failed IP selector initialization ", err)
	}

	for _, _net := range _ddIPSelector.nets {
		if _net.IP.To16() == nil && _net.IP.To4() == nil {
			t.Fatal("Encountered Unknown Network block")
		}
	}

	seed := make([]byte, 16)
	_, err = rand.Read(seed)
	if err != nil {
		t.Fatalf("Crypto/Rand error -- %s\n", err)
	}

	_, err = _ddIPSelector.selectIpAddr(seed)
	if err != nil {
		t.Fatalf("Error selecting decoy address -- %s\n", err)
	}
}
