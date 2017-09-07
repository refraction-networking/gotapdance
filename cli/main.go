package main

import (
	"flag"
	"fmt"
	"github.com/pkg/profile"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
	"os"
)

func main() {
	defer profile.Start().Stop()
	portPtr := flag.Int("port", 10500, "port number")
	flag.Parse()

	if *portPtr < 1 || *portPtr > 65535 {
		fmt.Println("Invalid port:", *portPtr)
		return
	}

	tapdanceProxy := tdproxy.NewTapDanceProxy(*portPtr)
	err := tapdanceProxy.ListenAndServe()
	if err != nil {
		tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
		os.Exit(1)
	}
}
