package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
	"github.com/mingyech/conjure-dns-registrar/pkg/encryption"
	"github.com/mingyech/conjure-dns-registrar/pkg/requester"
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
func run(requester *requester.Requester, msg string) error {
	defer requester.Close()

	recvBytes, err := requester.RequestAndRecv([]byte(msg))
	if err != nil {
		log.Printf("handle: %v\n", err)
	}
	log.Printf("Received: [%s]", string(recvBytes))
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

	pubkey, err := readKeyFromFile(pubkeyFilename)

	if err != nil {
		log.Fatal(err)
	}

	var req *requester.Requester
	if updaddr != "" {
		remoteAddr, err := net.ResolveUDPAddr("udp", updaddr)
		if err != nil {
			log.Fatal(err)
		}
		req, err = requester.NewUDPRequester(remoteAddr, basename, pubkey)
		if err != nil {
			log.Fatal(err)
		}
	}

	if dohaddr != "" || dotaddr != "" {
		if req != nil {
			fmt.Println("Only one of -udp, -doh, -dot may be provided")
			flag.Usage()
			os.Exit(2)
		}

		if dohaddr != "" {
			req, err = requester.NewDoHRequester(dohaddr, basename, pubkey, utlsDistribution)
			if err != nil {
				log.Fatal(err)
			}
		}
		if dotaddr != "" {
			if req != nil {
				fmt.Println("Only one of -udp, -doh, -dot may be provided")
				flag.Usage()
				os.Exit(2)
			}
			req, err = requester.NewDoTRequester(dotaddr, basename, pubkey, utlsDistribution)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	if req == nil {
		fmt.Println("One of -udp, -doh, -dot must be provided")
		flag.Usage()
		os.Exit(2)
	}

	if err != nil {
		log.Fatal(err)
	}

	err = run(req, msg)
	if err != nil {
		log.Fatal(err)
	}
}
