package tapdance

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSFailure(t *testing.T) {

	testUrls := map[string]string{
		"expiredTlsUrl":       "expired.badssl.com", // x509: certificate has expired or is not yet valid
		"wrongHostTlsUrl":     "wrong.host.badssl.com",
		"untrustedRootTlsUrl": "untrusted-root.badssl.com",
		"revokedTlsUrl":       "revoked.badssl.com",
		"pinningTlsUrl":       "pinning-test.badssl.com",
	}

	simpleRequest := "GET / HTTP/1.1\r\nHOST:%s\r\n\r\n"

	for issue, url := range testUrls {

		dialConn, err := net.Dial("tcp", url+":443")
		if err != nil {
			t.Fatalf("Failed when we shouldn't have: %v", err)
		}
		defer dialConn.Close()

		config := tls.Config{ServerName: url}
		tlsConn := tls.UClient(dialConn, &config, tls.HelloChrome_62)
		defer tlsConn.Close()

		request := fmt.Sprintf(simpleRequest, url)

		_, err = tlsConn.Write([]byte(request))
		if err != nil {
			t.Logf("%v - %v: [%v]", issue, url, err)
		} else {
			t.Logf("%v - %v: <no issue>", issue, url)
		}
	}

}

func TestSelectBoth(t *testing.T) {
	seed := []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
	}

	phantomIPAddr4, phantomIPAddr6, err := SelectPhantom(seed, both)
	require.Nil(t, err, "encountered err while selecting IPs")
	require.NotNil(t, phantomIPAddr4, "Failed to select IPv4 address (support: both")
	require.Equal(t, "192.122.190.252", phantomIPAddr4.String(), "Incorrect Address chosen")
	require.NotNil(t, phantomIPAddr6, "Failed to select IPv6 address (support: both")
	require.Equal(t, "2001:48a8:687f:1:fc9d:ee40:b05d:6656", phantomIPAddr6.String(), "Incorrect Address chosen")
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
	// if numDecoys < 5 {
	// 	t.Fatalf("Not enough V6 decoys in ClientConf (has: %v, need at least: %v)", numDecoys, 5)
	// }
}

func TestSelectDecoys(t *testing.T) {
	// SelectDecoys(sharedSecret []byte, useV6 bool, width uint) []*pb.TLSDecoySpec
	AssetsSetDir("./assets")
	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	if err != nil {
		t.Fatalf("Issue decoding seedStr")
	}
	decoys, err := SelectDecoys(seed, v6, 5)
	assert.Nil(t, err)
	if len(decoys) < 5 {
		t.Fatalf("Not enough decoys returned from selection.")
	}
	decoys, err = SelectDecoys(seed, v4, 5)
	assert.Nil(t, err)
	if len(decoys) < 5 {
		t.Fatalf("Not enough decoys returned from selection.")
	}
}

func copyFile(fromFile string, toFile string) error {
	from, err := os.Open(fromFile)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(toFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	return err
}

func TestSelectDecoysErrorHandling(t *testing.T) {
	dir := t.TempDir()
	err := copyFile("./assets/ClientConf.dev", dir+"/ClientConf")
	require.Nil(t, err)
	AssetsSetDir(dir)

	// SelectDecoys(sharedSecret []byte, useV6 bool, width uint)[]*pb.TLSDecoySpec
	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	if err != nil {
		t.Fatalf("Issue decoding seedStr")
	}

	// ====[ Assets dir doesn't exist ]=====
	_, err = AssetsSetDir("./non-existent-local-dir")
	require.Contains(t, err.Error(), "no such file or directory")

	// create temporary test dir
	dir = t.TempDir()
	defer os.RemoveAll(dir) // clean up
	_, err = AssetsSetDir(dir)
	require.Contains(t, err.Error(), "no such file or directory")

	// ====[ ClientConf file doesn't exist ]=====

	// => still using default configuration path since there was not file to update
	decoy, err := SelectDecoys(seed, both, 1)
	require.Nil(t, err)
	require.NotNil(t, decoy)
	assert.Equal(t, "tapdance1.freeaeskey.xyz", decoy[0].GetHostname())

	// ====[ ClientConf file is empty ]=====

	// create temporary ClientConf file in temp test Dir
	tmpfile, err := ioutil.TempFile(dir, "ClientConf")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	// Error occurs while updating assets dir, clientconf remains unchanged from
	// default from initialization.
	_, err = AssetsSetDir(dir)
	require.Nil(t, err)

	err = Assets().readConfigs()
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "no such file or directory")

	// => still using default configuration path since there was not file to update
	decoy, err = SelectDecoys(seed, both, 1)
	require.Nil(t, err)
	require.NotNil(t, decoy)
	assert.Equal(t, "tapdance1.freeaeskey.xyz", decoy[0].GetHostname())

	// ====[ ClientConf file not formatted as protobuf ]=====

	tmpfn := filepath.Join(dir, "ClientConf")
	content := []byte("temporary file's content")
	if err := ioutil.WriteFile(tmpfn, content, 0666); err != nil {
		log.Fatal(err)
	}

	// => still using default configuration path since there was not file to update
	decoy, err = SelectDecoys(seed, both, 1)
	require.Nil(t, err)
	require.NotNil(t, decoy)
	assert.Equal(t, "tapdance1.freeaeskey.xyz", decoy[0].GetHostname())
}
