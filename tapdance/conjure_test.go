package tapdance

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestUseV4(t *testing.T) {
	v6S := V6{
		support: true,
		include: v6,
		checked: time.Now(),
	}
	cjSession := ConjureSession{V6Support: v6S}
	if cjSession.useV4() != false {
		t.Fatal("Incorrect v4 usage determination")
	}

	cjSession.setV6Support(v4)
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
	// generated using
	// echo "customString" | hmac256 "1abcd2efgh3ijkl4"
	// soln1Str := "d209c99ea22606e5b990a770247b0cd005c157208cb7194fef407fe3fa7e9266"
	soln1Str := "d10b84f9e2cc57bb4294b8929a3fca25cce7f95eb226fa5bcddc5417e1d2eac2"

	soln1 := make([]byte, hex.DecodedLen(len(soln1Str)))
	hex.Decode(soln1, []byte(soln1Str))

	test1 := conjureHMAC([]byte("1abcd2efgh3ijkl4"), "customString")
	test1Str := make([]byte, hex.EncodedLen(len(test1)))
	hex.Encode(test1Str, test1)

	if len(test1) != len(soln1) {
		t.Fatalf("Wrong hash Length:\n%s\n%s", soln1Str, test1Str)
	}

	if !hmac.Equal(test1, soln1) {
		t.Fatalf("Wrong hash returned:\n%s\n%s", soln1Str, test1Str)
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

	// t.Logf("V6 Decoys: %v", numDecoys)
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
	decoys := SelectDecoys(seed, v6, 5)
	if len(decoys) < 5 {
		t.Fatalf("Not enough decoys returned from selection.")
	}
	decoys = SelectDecoys(seed, v4, 5)
	if len(decoys) < 5 {
		t.Fatalf("Not enough decoys returned from selection.")
	}
}
