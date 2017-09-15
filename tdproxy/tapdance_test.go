package tdproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

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

	tapdanceProxy := NewTapDanceProxy(10600)
	go tapdanceProxy.ListenAndServe()
	time.Sleep(2 * time.Second)

	tapdance.AssetsFromDir("../assets/")
	err := tapdance.Assets().SetGeneration(100500)
	if err != nil {
		t.Fatalf(err.Error())
	}
	tapdance1Hostname := "tapdance1.freeaeskey.xyz"
	tapdance1Ipv4 := binary.BigEndian.Uint32(net.ParseIP("192.122.190.104").To4())
	tapdance1Decoy := tapdance.TLSDecoySpec{Hostname: &tapdance1Hostname,
		Ipv4Addr: &tapdance1Ipv4}
	err = tapdance.Assets().SetDecoys([]*tapdance.TLSDecoySpec{&tapdance1Decoy})
	if err != nil {
		t.Fatalf(err.Error())
	}

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
	resource := "https://sendseq.benjaminvandersloot.com/" + string(x)

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
