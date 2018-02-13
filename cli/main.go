package main

import (
	"flag"
	"os"
	"strings"

	"github.com/pkg/profile"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
)

func main() {
	defer profile.Start().Stop()

	portPtr := flag.Int("p", 10500, "HTTP proxy port")
	hostPtr := flag.String("h", "tapdance2.freeaeskey.xyz", "overt host to request resources from")
<<<<<<< HEAD
	resourcesPtr := flag.String("r", "/flowers/index.htm", "comma separated list of resources to request")

	headlessHostPtr := flag.String("hh", "localhost", "headless browser host")
	headlessPortPtr := flag.Int("hp", 9222, "headless browser port")

=======
	resourcesPtr := flag.String("r", "/large-file.dat", "comma separated list of resources to request")
>>>>>>> dittotap-mock
	flag.Parse()

	tapdanceProxy := tdproxy.NewTapDanceProxy(*portPtr)
	tapdance.OvertHost = *hostPtr
	tapdance.OvertResources = strings.Split(*resourcesPtr, ",")

	tapdance.HeadlessHost = *headlessHostPtr
	tapdance.HeadlessPort = *headlessPortPtr

	err := tapdanceProxy.ListenAndServe()
	if err != nil {
		tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
		os.Exit(1)
	}
}
