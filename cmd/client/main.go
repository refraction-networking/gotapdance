package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
)

func handle(pconn net.PacketConn, remoteAddr *net.UDPAddr, msg string) error {
	defer func() {
		log.Printf("end stream :%s\n", remoteAddr.String())
	}()
	log.Printf("begin stream :%s\n", remoteAddr.String())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()

		_, err := pconn.WriteTo([]byte(msg), remoteAddr)

		log.Printf("stream :%s write: [%s], err: %v\n", remoteAddr.String(), msg, err)
	}()
	go func() {
		defer wg.Done()
		var buf [4096]byte
		_, recvAddr, err := pconn.ReadFrom(buf[:])
		response := string(buf[:])
		log.Printf("stream: %s: server: %s: read: [%s], err: %v\n", remoteAddr.String(), recvAddr.String(), response, err)
	}()
	wg.Wait()

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
	flag.StringVar(&addr, "addr", "", "address of DNS resolver")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
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

	msg := "hi"

	pconn = NewDNSPacketConn(pconn, remoteAddr, basename)
	err = run(basename, remoteAddr, pconn, msg)
	if err != nil {
		log.Fatal(err)
	}
}
