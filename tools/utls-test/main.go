package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	pb "github.com/refraction-networking/conjure/proto"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

var (
	fingerprints = []utls.ClientHelloID{utls.HelloChrome_62, utls.HelloChrome_72, utls.HelloChrome_83}
	dialTimeout  = time.Duration(5) * time.Second
)

func HttpGetByHelloID(hostname string, addr string, helloID utls.ClientHelloID) (*http.Response, error) {
	config := utls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := utls.UClient(dialConn, &config, helloID)

	err = uTlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return nil, err
	}

	defer uTlsConn.Close()

	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	response, err := httpGetOverConn(uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol, hostname)
	if err == nil {
		response.TLS = &tls.ConnectionState{
			Version:     uTlsConn.ConnectionState().Version,
			CipherSuite: uTlsConn.ConnectionState().CipherSuite}
	}
	return response, err
}

func httpGetOverConn(conn net.Conn, alpn string, requestHostname string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Host: requestHostname + "/"},
		Header: make(http.Header),
		Host:   requestHostname,
	}

	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(conn)
		if err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	default:
		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
	}
}

func worker(id int, decoys <-chan *pb.TLSDecoySpec, results chan<- string, wg *sync.WaitGroup) {
	var rsp *http.Response
	var err error
	var workerTotal int = 0

	defer wg.Done()

	for d := range decoys {
		workerTotal++
		for _, fp := range fingerprints {

			requestHostname := d.GetHostname()
			requestAddr := d.GetIpAddrStr()

			rsp, err = HttpGetByHelloID(requestHostname, requestAddr, fp)
			if err != nil {
				results <- fmt.Sprintf("#%v [%v]> %s - %s -%s failed: %+v\n",
					id, workerTotal, fp.Str(), requestAddr, requestHostname, err)
			} else {
				results <- fmt.Sprintf("#%v [%v]> %s - %s - %s response: %v - %v - %v - %s\n",
					id, workerTotal, fp.Str(), requestAddr, requestHostname, rsp.StatusCode,
					rsp.TLS.Version, rsp.TLS.CipherSuite, rsp.Header)
				// results <- fmt.Sprintf(out, "#> %s - %s - %s response: %+s\n", fp.Str(), requestAddr, requestHostname, dumpResponseNoBody(response))
			}
		}
	}
	fmt.Printf("worker %v shutting down\n", id)
}

func dumpResponseNoBody(response *http.Response) string {
	resp, err := httputil.DumpResponse(response, false)
	if err != nil {
		return fmt.Sprintf("failed to dump response: %v", err)
	}

	return string(resp)
}

func parseClientConf(fname string) pb.ClientConf {

	clientConf := pb.ClientConf{}
	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}
	err = proto.Unmarshal(buf, &clientConf)
	if err != nil {
		log.Fatal("Error parsing ClientConf", err)
	}
	return clientConf
}

func main() {

	var assetsFile = flag.String("f", "ClientConf", "The ClientConf")
	var outFilename = flag.String("o", "", "`output` file name to write new/modified config")
	var workers = flag.Int("w", 10, "Number of worker threads to spawn")
	flag.Parse()

	fmt.Printf("Attempting connections for ClientConf (%s) \n", *assetsFile)

	if *assetsFile == "" {
		fmt.Println("Please provide a clientConf file.")
		os.Exit(1)
	}

	// Parse ClientConf
	clientConf := pb.ClientConf{}
	clientConf = parseClientConf(*assetsFile)

	var allDecoys = clientConf.DecoyList.GetTlsDecoys()
	var decoys = make(chan *pb.TLSDecoySpec, len(allDecoys))
	var results = make(chan string, len(allDecoys)*len(fingerprints))
	var wg sync.WaitGroup
	var out io.Writer = os.Stdout

	if *outFilename != "" {
		f, err := os.OpenFile(*outFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(i, decoys, results, &wg)
	}

	for _, decoy := range allDecoys {
		decoys <- decoy
	}
	close(decoys)

	var printTotal int = 0
	for j := 0; j < len(allDecoys)*len(fingerprints); j++ {
		r := <-results
		printTotal++
		fmt.Fprintf(out, "(%v) %s", printTotal, r)
	}

	wg.Wait()
}
