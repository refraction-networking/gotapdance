package tapdance

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestTapDanceDial(t *testing.T) {
	var b bytes.Buffer
	logHolder := bufio.NewWriter(&b)
	oldLoggerOut := Logger().Out
	Logger().Out = logHolder
	defer func() {
		Logger().Out = oldLoggerOut
		if t.Failed() {
			logHolder.Flush()
			fmt.Printf("TapDance log was:\n%s\n", b.String())
		}
	}()
	urlParse := func(urlStr string) url.URL {
		_url, err := url.Parse(urlStr)
		if err != nil {
			panic(err)
		}
		return *_url
	}
	testUrls := []url.URL{
		urlParse("http://detectportal.firefox.com:80/success.txt"),
		urlParse("https://tapdance1.freeaeskey.xyz:443/"),
	}

	getResponseString := func(url url.URL,
		dial func(network, address string) (net.Conn, error)) (string, error) {
		conn, err := dial("tcp", url.Hostname()+":"+url.Port())
		if err != nil {
			return "", errors.New(fmt.Sprintf("dial failed: %v", err))
		}
		if url.Scheme == "https" {
			conn = tls.Client(conn, &tls.Config{ServerName: url.Hostname()})
		}

		req, err := http.NewRequest("GET", url.String(), nil)
		req.Host = url.Hostname()
		if err != nil {
			return "", errors.New(fmt.Sprintf("http.NewRequest failed: %v", err))
		}

		err = req.Write(conn)
		if err != nil {
			return "", errors.New(fmt.Sprintf("Write failed: %v", err))
		}

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return "", errors.New(fmt.Sprintf("http.ReadResponse failed: %v", err))
		}

		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New(fmt.Sprintf("ioutil.ReadAll failed: %v", err))
		}
		return string(responseBody), nil
	}

	for _, testUrl := range testUrls {
		referenceResponse, err := getResponseString(testUrl, net.Dial)
		if err != nil {
			t.Fatalf("Failed to get reference response: %v. Check your connection", err)
		}
		tdResponse, err := getResponseString(testUrl, Dial)
		if err != nil {
			t.Fatalf("Failed to get response via TapDance: %v.", err)
		}
		if string(referenceResponse) != string(tdResponse) {
			t.Fatalf("Unexpected response from %s\nExpected: %s\nGot: %s",
				testUrl.String(), string(referenceResponse), string(tdResponse))
		}
	}
}
