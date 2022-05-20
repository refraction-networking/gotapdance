package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
)

func main() {
	var addr string
	flag.StringVar(&addr, "addr", "", "address of DNS resolver")
	flag.Parse()
	if addr == "" {
		fmt.Println("DNS resolver address must be specified")
		flag.Usage()
		os.Exit(2)
	}

	var remoteAddr net.Addr
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

	pconn = NewDNSPacketConn(pconn, remoteAddr, domain)
}
