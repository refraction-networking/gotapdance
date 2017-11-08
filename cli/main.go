package main

import (
	"flag"
	"github.com/pkg/profile"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
	"os"
)

func main() {
	defer profile.Start().Stop()

	var port = flag.Int("port", 10500, "TapDance will listen for connections on this port.")
	var assets_location = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
	flag.Parse()

	tapdance.AssetsFromDir(*assets_location)

	tapdanceProxy := tdproxy.NewTapDanceProxy(*port)
	err := tapdanceProxy.ListenAndServe()
	if err != nil {
		tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
		os.Exit(1)
	}
}
