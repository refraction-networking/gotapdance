package tapdance

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestUseV4(t *testing.T) {
	v6 := V6{
		support: true,
		checked: time.Now(),
	}
	cjSession := ConjureSession{V6Support: v6}
	if cjSession.useV4() != false {
		t.Fatal("Incorrect v4 usage determination")
	}

	cjSession.V6Support.support = false
	if cjSession.useV4() != true {
		t.Fatal("Incorrect v4 usage determination")
	}

	cjSession.V6Support.checked = time.Now().Add(-3 * time.Hour)
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
	} else if darDecoyIPAddr.String() != "2001:48a8:687f:1:709:b0d:f11:121e" {
		t.Fatalf("Incorrect Address chosen: %s", darDecoyIPAddr.String())

	}
}

func TestConjureHMAC(t *testing.T) {

	solution1 := []byte{
		0x09, 0xd2, 0x9e, 0xc9, 0x26, 0xa2, 0xe5, 0x06, 0x90, 0xb9, 0x70, 0xa7, 0x7b, 0x24, 0xd0, 0x0c,
		0xc1, 0x05, 0x20, 0x57, 0xb7, 0x8c, 0x4f, 0x19, 0x40, 0xef, 0xe3, 0x7f, 0x7e, 0xfa, 0x66, 0x92}
	test1 := conjureHMAC([]byte("1abcd2efgh3ijkl4"), "customString")
	if len(test1) != len(solution1) {
		t.Fatalf("Wrong hash returned:\n%v\n%v", solution1, test1)
	}
	for i, v := range test1 {
		if v != solution1[i] {
			t.Fatalf("Wrong hash returned:\n%v\n%v", solution1, test1)
		}
	}
}

func TestGenerateKeys(t *testing.T) {
	fakePubkey := [32]byte{0}
	keys, err := generateSharedKeys(fakePubkey)
	if err != nil {
		t.Fatalf("Failed to generate Conjure Keys: %v", err)
	}
	if keys == nil {
		t.Fatalf("Incorrect Keys generated: %v", keys.SharedSecret)
	}
}

func TestRegDigest(t *testing.T) {
	reg := ConjureReg{}
	soln1 := "{result:\"no stats tracked\"}"

	if reg.digestStats() != soln1 {
		t.Fatalf("Incorrect stats digest returned")
	}

	testRTT := uint32(1000)
	reg.stats = &pb.SessionStats{
		TotalTimeToConnect: &testRTT,
		TcpToDecoy:         &testRTT}

	soln2 := "{result:\"success\", tcp_to_decoy:1000, tls_to_decoy:0, total_time_to_connect:1000}"
	if reg.digestStats() != soln2 {
		t.Fatalf("Incorrect stats digest returned")
	}

	reg.stats.TlsToDecoy = &testRTT

	soln3 := "{result:\"success\", tcp_to_decoy:1000, tls_to_decoy:1000, total_time_to_connect:1000}"
	if reg.digestStats() != soln3 {
		t.Fatalf("Incorrect stats digest returned")
	}
}

func TestCheckV6Decoys(t *testing.T) {
	AssetsSetDir("./assets")
	decoysV6 := Assets().GetV6Decoys()
	numDecoys := len(decoysV6)

	for _, decoy := range decoysV6 {
		if decoy.Ipv4Addr != nil {
			// If a decoys Ipv4 address is defined it will ignore the IPv6 address
			numDecoys--
		}
	}

	t.Logf("V6 Decoys: %v", numDecoys)
	if numDecoys < 5 {
		t.Fatalf("Not enough V6 decoys in ClientConf (has: %v, need at least: %v)", numDecoys, 5)
	}
}

func TestSelectDecoys(t *testing.T) {
	// SelectDecoys(sharedSecret []byte, useV6 bool, width uint) []*pb.TLSDecoySpec
	AssetsSetDir("./assets")
	seedStr := []byte("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	seed := make([]byte, hex.DecodedLen(len(seedStr)))
	n, err := hex.Decode(seed, seedStr)
	if err != nil || n != 32 {
		t.Fatalf("Issue decoding seedStr")
	}
	decoys := SelectDecoys(seed, true, 5)
	if len(decoys) < 5 {
		t.Fatalf("Not enough decoys returned from selection.")
	}
	decoys = SelectDecoys(seed, false, 5)
	if len(decoys) < 5 {
		t.Fatalf("Not enough decoys returned from selection.")
	}
}
