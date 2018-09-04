package tapdance

import (
	"bufio"
	"crypto/tls"
	"fmt"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
)

func setupTestAssets() error {
	tmpDir, err := ioutil.TempDir("/tmp/", "td-test-")
	if err != nil {
		return err
	}
	AssetsSetDir(tmpDir)
	// make sure station won't send new ClientConf
	err = Assets().SetGeneration(100500)
	if err != nil {
		return err
	}

	// use testing public key
	keyType := pb.KeyType_AES_GCM_128
	stationTestPubkey, err := ioutil.ReadFile("../assets/station_pubkey_test")
	if err != nil {
		return err
	}

	pubKey := pb.PubKey{
		Key:  stationTestPubkey,
		Type: &keyType,
	}
	if err != nil {
		return err
	}
	Assets().SetPubkey(pubKey)

	// use correct decoy
	tapdance1Decoy := pb.InitTLSDecoySpec("192.122.190.104", "tapdance1.freeaeskey.xyz")
	err = Assets().SetDecoys([]*pb.TLSDecoySpec{tapdance1Decoy})
	if err != nil {
		return err
	}
	return nil
}

func TestMain(m *testing.M) {
	err := setupTestAssets()
	if err != nil {
		panic(err)
	}
	retCode := m.Run()
	os.Exit(retCode)
}

func TestTapDanceDial(t *testing.T) {
	urlParse := func(urlStr string) url.URL {
		_url, err := url.Parse(urlStr)
		if err != nil {
			panic(err)
		}
		return *_url
	}
	testUrls := []url.URL{
		// TODO: uncomment when/if :80 is allowed on all stations
		// urlParse("http://detectportal.firefox.com:80/success.txt"),
		urlParse("https://tapdance1.freeaeskey.xyz:443/"),
	}

	getResponseString := func(url url.URL,
		dial func(network, address string) (net.Conn, error)) (string, error) {
		conn, err := dial("tcp", url.Hostname()+":"+url.Port())
		if err != nil {
			return "", fmt.Errorf("dial failed: %v", err)
		}
		if url.Scheme == "https" {
			conn = tls.Client(conn, &tls.Config{ServerName: url.Hostname()})
		}
		defer conn.Close()

		req, err := http.NewRequest("GET", url.String(), nil)
		req.Host = url.Hostname()
		if err != nil {
			return "", fmt.Errorf("http.NewRequest failed: %v", err)
		}

		err = req.Write(conn)
		if err != nil {
			return "", fmt.Errorf("Write failed: %v", err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return "", fmt.Errorf("http.ReadResponse failed: %v", err)
		}

		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("ioutil.ReadAll failed: %v", err)
		}
		return string(responseBody), nil
	}

	for _, testUrl := range testUrls {
		referenceResponse, err := getResponseString(testUrl, net.Dial)
		if err != nil {
			t.Fatalf("Failed to get reference response from %v : %v. Check your connection",
				testUrl, err)
		}
		tdResponse, err := getResponseString(testUrl, Dial)
		if err != nil {
			t.Fatalf("Failed to get response from %v via TapDance: %v.", testUrl, err)
		}
		if string(referenceResponse) != string(tdResponse) {
			t.Fatalf("Unexpected response from %s\nExpected: %s\nGot: %s",
				testUrl.String(), string(referenceResponse), string(tdResponse))
		}
	}
}
