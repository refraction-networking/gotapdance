package tdproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os/exec"
	"testing"
	"time"
)

func asTestHandshakeLaunchProxy(t *testing.T) {
	// hangs, as it fails to read anything from nc
	// TODO: check if got an expected result during a handshake
	var errChan = make(chan error, 0)
	go func() {
		// exec, because has to be different process
		time.Sleep(time.Second * 5)
		grepCmd := exec.Command("wget", "-e", "use_proxy=yes", "-e", "127.0.0.1:10500", "https://twitter.com")
		grepOut, _ := grepCmd.StdoutPipe()
		grepCmd.Start()
		grepBytes, err := ioutil.ReadAll(grepOut)
		errChan <- err
		grepCmd.Wait()
		fmt.Println(grepBytes)
	}()
	tap_dance_proxy := NewTapDanceProxy(10500)
	go func() {
		err := tap_dance_proxy.ListenAndServe()
		errChan <- err
	}()
	err := <-errChan
	tap_dance_proxy.Stop()
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
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

	tapdanceProxy := NewTapDanceProxy(10600)
	go tapdanceProxy.ListenAndServe()
	time.Sleep(10 * time.Second)
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
