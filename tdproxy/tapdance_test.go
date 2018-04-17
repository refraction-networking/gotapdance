package tdproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func setupTestAssets() error {
	tmpDir, err := ioutil.TempDir("/tmp/", "td-test-")
	if err != nil {
		return err
	}
	tapdance.AssetsSetDir(tmpDir)
	// make sure station won't send new ClientConf
	err = tapdance.Assets().SetGeneration(100500)
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
	tapdance.Assets().SetPubkey(pubKey)

	// use correct decoy
	tapdance1Decoy := pb.InitTLSDecoySpec("192.122.190.104", "tapdance1.freeaeskey.xyz")
	err = tapdance.Assets().SetDecoys([]*pb.TLSDecoySpec{tapdance1Decoy})
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

func TestSendSeq(t *testing.T) {
	buf := new(bytes.Buffer)
	for i := 0; i < 8192; i++ {
		h := fmt.Sprintf("%04x", i)
		for j := 0; j < 4; j++ {
			err := binary.Write(buf, binary.BigEndian, h[j])
			if err != nil {
				t.Fatalf("binary.Write failed: %s\n", err)
			}
		}
	}

	// start TapDance proxy
	tapdanceProxy := NewTapDanceProxy(10600)
	go tapdanceProxy.ListenAndServe()
	time.Sleep(2 * time.Second)

	// create proxyClient that will use TapDance proxy
	proxyUrl, err := url.Parse("http://127.0.0.1:10600")
	if err != nil {
		t.Fatalf(err.Error())
	}
	proxyClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		t.Fatalf("%s\n", err.Error())
	}
	x := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(x, b)
	resource := "https://sendseq.sfrolov.io/" + string(x)

	var bufBytes []byte
	bufBytes, _ = ioutil.ReadAll(buf)
	buf = bytes.NewBuffer(bufBytes)

	resp, err := proxyClient.Post(resource, "text/plain", buf)
	if err != nil {
		t.Fatalf("Proxy POST error : %s\n", err.Error())
	}
	if resp.StatusCode != 200 {
		t.Fatalf("POST status %d\n", resp.StatusCode)
	}
	time.Sleep(time.Second)
	resp2, err2 := http.Get(resource)
	if err2 != nil {
		t.Fatalf("GET error: %s\n", err.Error())
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("POST status %d\n", resp.StatusCode)
	}

	tmpPost := new(bytes.Buffer)
	tmpPost.ReadFrom(resp.Body)
	bufPost := tmpPost.Bytes()
	tmpGet := new(bytes.Buffer)
	tmpGet.ReadFrom(resp2.Body)
	bufGet := tmpPost.Bytes()
	if len(bufBytes) != len(bufGet) {
		t.Fatalf("Mismatch length (sent from decoyclient, recd by webserver): (%d, %d)\n", len(bufBytes), len(bufGet))
	}
	for i := 0; i < len(bufBytes); i++ {
		if bufBytes[i] != bufGet[i] {
			t.Fatalf("Mismatch content, byte %d (sent by decoyclient, recd by webserver)\n", i)
		}
	}
	if len(bufGet) != len(bufPost) {
		t.Fatalf("Mismatch length (sent from webserver, recd by decoyclient): (%d, %d)\n", len(bufGet), len(bufPost))
	}
	for i := 0; i < len(bufGet); i++ {
		if bufGet[i] != bufPost[i] {
			t.Fatalf("Mismatch content, byte %d (sent by webserver, recd by decoyclient)\n", i)
		}
	}
	resp.Body.Close()
	resp2.Body.Close()
	_, _ = http.Post(resource, "text/plain", bytes.NewBuffer([]byte("0")))
	return
}
