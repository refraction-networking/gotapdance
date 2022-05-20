package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("addr: ", remoteAddr)
}
