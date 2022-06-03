package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
	"github.com/mingyech/conjure-dns-registrar/pkg/encryption"
	"github.com/mingyech/conjure-dns-registrar/pkg/turbotunnel"
	utls "github.com/refraction-networking/utls"
)

const (
	bufSize   = 4096
	maxMsgLen = 140
)

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return encryption.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

func handle(pconn net.PacketConn, remoteAddr net.Addr, msg string, pubkey []byte) error {
	encryption.ListenMessages(pconn)
	for {
		econn, err := encryption.NewClient(pconn, remoteAddr, pubkey)
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}

		_, err = econn.Write([]byte(msg))
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}

		log.Printf("Sent: [%s]\n", msg)

		var responseBuf [maxMsgLen]byte
		_, err = econn.Read(responseBuf[:])

		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}

		response := string(responseBuf[:])
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		log.Printf("Response: [%s]\n", response)
		return nil
	}

}

func run(domain dns.Name, remoteAddr net.Addr, pconn net.PacketConn, msg string, pubkey []byte) error {
	defer pconn.Close()

	err := handle(pconn, remoteAddr, msg, pubkey)
	if err != nil {
		log.Printf("handle: %v\n", err)
	}
	return nil
}

func main() {
	var updaddr string
	var domain string
	var msg string
	var pubkeyFilename string
	var dohaddr string
	var dotaddr string
	var utlsDistribution string
	flag.StringVar(&updaddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&dohaddr, "doh", "", "address of DoH DNS resolver")
	flag.StringVar(&dotaddr, "dot", "", "address of DoT DNS resolver")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
	flag.StringVar(&msg, "msg", "hi", "message to send")
	flag.StringVar(&pubkeyFilename, "pubkey", "", "server public key")
	flag.StringVar(&utlsDistribution, "utls",
		"3*Firefox_65,1*Firefox_63,1*iOS_12_1",
		"choose TLS fingerprint from weighted distribution")
	flag.Parse()
	if pubkeyFilename == "" {
		fmt.Println("Server public key must be provided")
		flag.Usage()
		os.Exit(2)
	}

	if domain == "" {
		fmt.Println("domain must be specified")
		flag.Usage()
		os.Exit(2)
	}

	basename, err := dns.ParseName(domain)

	if err != nil {
		log.Fatal(err)
	}

	var pconn net.PacketConn
	var remoteAddr net.Addr
	if updaddr != "" {
		remoteAddr, err = net.ResolveUDPAddr("udp", updaddr)
		if err != nil {
			log.Fatal(err)
		}
		pconn, err = net.ListenUDP("udp", nil)

		if err != nil {
			log.Fatal(err)
		}

	}
	if dohaddr != "" || dotaddr != "" {
		if pconn != nil {
			fmt.Println("Only one of -udp, -doh, -dot may be provided")
			flag.Usage()
			os.Exit(2)
		}

		utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
		if utlsClientHelloID != nil {
			log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
		}

		if dohaddr != "" {
			remoteAddr = turbotunnel.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			pconn, err = NewHTTPPacketConn(rt, dohaddr, 32)
			if err != nil {
				log.Fatal(err)
			}
		}
		if dotaddr != "" {
			if pconn != nil {
				fmt.Println("Only one of -udp, -doh, -dot may be provided")
				flag.Usage()
				os.Exit(2)
			}

			remoteAddr = turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			pconn, err = NewTLSPacketConn(dotaddr, dialTLSContext)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	if pconn == nil {
		fmt.Println("One of -udp, -doh, -dot must be provided")
		flag.Usage()
		os.Exit(2)
	}

	pubkey, err := readKeyFromFile(pubkeyFilename)

	if err != nil {
		log.Fatal(err)
	}

	pconn = NewDNSPacketConn(pconn, remoteAddr, basename)
	err = run(basename, remoteAddr, pconn, msg, pubkey)
	if err != nil {
		log.Fatal(err)
	}
}
