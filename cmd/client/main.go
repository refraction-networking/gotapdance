package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
)

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

func handle(pconn net.PacketConn, remoteAddr *net.UDPAddr, msg string) error {
	defer func() {
		log.Printf("end stream :%d", remoteAddr)
	}()
	log.Printf("begin stream :%d", remoteAddr)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(remote, local)
		remote.ReadFrom(local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream :%d copy stream←local: %v", remoteAddr, err)
		}
		local.CloseRead()
		remote.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, remote)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream :%d copy local←stream: %v", remoteAddr, err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return nil
}

func run(domain dns.Name, remoteAddr *net.UDPAddr, pconn net.PacketConn, msg string) error {
	defer pconn.Close()

	go func() {
		err := handle(pconn, remoteAddr, msg)
		if err != nil {
			log.Printf("handle: %v", err)
		}
	}()
}

func main() {
	var addr string
	flag.StringVar(&addr, "addr", "", "address of DNS resolver")
	flag.Parse()
	if addr == "" {
		fmt.Println("DNS resolver address must be specified")
		flag.Usage()
		os.Exit(2)
	}

	var pconn net.PacketConn
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}

	pconn, err = net.ListenUDP("udp", nil)

	fmt.Println("addr: ", remoteAddr)

	msg := "hi"

	pconn = NewDNSPacketConn(pconn, remoteAddr, domain)
	err = run(domain, remoteAddr, pconn, msg)
	if err != nil {
		log.Fatal(err)
	}
}
