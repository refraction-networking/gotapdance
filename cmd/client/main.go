package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
)

const (
	bufSize = 4096
)

func handle(pconn net.PacketConn, remoteAddr *net.UDPAddr, msg string) error {
	_, err := pconn.WriteTo([]byte(msg), remoteAddr)
	if err != nil {
		log.Fatalf("stream :%s write: [%s], err: %v\n", remoteAddr.String(), msg, err)
	}

	var buf [bufSize]byte

	_, recvAddr, err := pconn.ReadFrom(buf[:])
	response := string(buf[:])
	if err != nil {
		log.Fatalf("stream: %s: server: %s: read: [%s], err: %v\n", remoteAddr.String(), recvAddr.String(), response, err)
	}
	fmt.Printf("Response: [%s]\n", response)

	return nil
}

func run(domain dns.Name, remoteAddr *net.UDPAddr, pconn net.PacketConn, msg string) error {
	defer pconn.Close()

	// TODO: add encryption
	err := handle(pconn, remoteAddr, msg)
	if err != nil {
		log.Printf("handle: %v\n", err)
	}
	return nil
}

func main() {
	var addr string
	var domain string
	var msg string
	flag.StringVar(&addr, "addr", "", "address of DNS resolver")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
	flag.StringVar(&msg, "msg", "hi", "message to send")
	flag.Parse()
	if addr == "" {
		fmt.Println("DNS resolver address must be specified")
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

	pconn = NewDNSPacketConn(pconn, remoteAddr, basename)
	err = run(basename, remoteAddr, pconn, msg)
	if err != nil {
		log.Fatal(err)
	}
}
