package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
	"github.com/mingyech/conjure-dns-registrar/pkg/encryption"
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
	var addr string
	var domain string
	var msg string
	var pubkeyFilename string
	flag.StringVar(&addr, "addr", "", "address of DNS resolver")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
	flag.StringVar(&msg, "msg", "hi", "message to send")
	flag.StringVar(&pubkeyFilename, "pubkey", "", "server public key")
	flag.Parse()
	if addr == "" {
		fmt.Println("DNS resolver address must be specified")
		flag.Usage()
		os.Exit(2)
	}

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

	var pconn net.PacketConn
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	basename, err := dns.ParseName(domain)

	if err != nil {
		log.Fatal(err)
	}

	pconn, err = net.ListenUDP("udp", nil)

	if err != nil {
		log.Fatal(err)
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
