package main

import (
	"github.com/SergeyFrolov/gotapdance/tapdance"
	"flag"
	"fmt"
)

func main() {

	portPtr := flag.Int("port", 10500, "port number")
	flag.Parse()

	if (*portPtr < 1 || *portPtr > 65535) {
		fmt.Println("Invalid port:", *portPtr)
		return
        }

	tapdanceProxy := tapdance.NewTapdanceProxy(*portPtr)
	tapdanceProxy.Listen()
}
