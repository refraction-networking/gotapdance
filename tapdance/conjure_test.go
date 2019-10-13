package tapdance

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestUseV4(t *testing.T) {
	v6 := V6{
		support: true,
		checked: time.Now(),
	}
	cjSession := ConjureSession{v6Support: v6}
	if cjSession.useV4() != false {
		t.Fatal("Incorrect v4 usage determination")
	}

	cjSession.v6Support.support = false
	if cjSession.useV4() != true {
		t.Fatal("Incorrect v4 usage determination")
	}

	cjSession.v6Support.checked = time.Now().Add(-3 * time.Hour)
	if cjSession.useV4() != false {
		t.Fatal("Incorrect v4 usage determination")
	}
}

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

	seed = []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
	}

	darDecoyIPAddr, err = SelectPhantom(seed, false)
	if err != nil || darDecoyIPAddr == nil {
		t.Fatalf("Failed to select IP address (v6: false): %v", err)
	} else if darDecoyIPAddr.String() != "192.122.190.120" {
		t.Fatalf("Incorrect Address chosen")
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

	seed = []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
	}

	darDecoyIPAddr, err := SelectPhantom(seed, true)
	if err != nil || darDecoyIPAddr == nil {
		t.Fatalf("Failed to select IP address (v6: true): %v", err)
	} else if darDecoyIPAddr.String() != "1234::507:90c:e17:181a" {
		t.Fatalf("Incorrect Address chosen")

	}
}
