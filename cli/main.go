package main

import (
	"github.com/pkg/profile"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
	"os"
	"flag"
)

func main() {
	defer profile.Start().Stop()

	var port = flag.Int("port", 10500, "TapDance will listen for connections on this port.")
	flag.Parse()

	tapdanceProxy := tdproxy.NewTapDanceProxy(*port)
	err := tapdanceProxy.ListenAndServe()
	if err != nil {
		tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
		os.Exit(1)
	}
}
