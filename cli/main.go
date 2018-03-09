package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/pkg/profile"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
	"net"
	"os"
	"runtime"
	"strings"
)

func main() {
	var chromePath string
	switch runtime.GOOS {
	case "darwin":
		flag.StringVar(&chromePath, "chrome_path",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"Path to Google Chrome binary.")
	case "linux":
		flag.StringVar(&chromePath, "chrome_path",
			"/usr/bin/google-chrome-beta",
			"Path to Google Chrome binary.")
	}

	portPtr := flag.Int("p", 10500, "HTTP proxy port")
	resourcesPtr := flag.String("r", "/flowers/index.htm", "comma separated list of resources to request")

	var decoy = flag.String("decoy", "tapdance2.freeaeskey.xyz", "Single decoy to use. Accepts \"SNI,IP\" or simply \"SNI\""+
		" — IP will be resolved. Examples: \"site.io,1.2.3.4\", \"site.io\"")
	var assets_location = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
	flag.Parse()
	tapdance.ChromePath = chromePath

	defer profile.Start().Stop()

	tapdance.OvertHost = *decoy
	tapdance.OvertResources = strings.Split(*resourcesPtr, ",")

	tapdance.AssetsFromDir(*assets_location)
	if *decoy != "" {
		err := setSingleDecoyHost(*decoy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set single decoy host: %s\n", err)
			flag.Usage()
			os.Exit(255)
		}
	}

	tapdanceProxy := tdproxy.NewTapDanceProxy(*portPtr)

	err := tapdanceProxy.ListenAndServe()
	if err != nil {
		tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
		os.Exit(1)
	}
}

func setSingleDecoyHost(decoy string) error {
	splitDecoy := strings.Split(decoy, ",")

	var ip string
	switch len(splitDecoy) {
	case 1:
		ips, err := net.LookupHost(decoy)
		if err != nil {
			return err
		}
		ip = ips[0]
	case 2:
		ip = splitDecoy[1]
		if net.ParseIP(ip) == nil {
			return errors.New("provided IP address \"" + ip + "\" is invalid")
		}
	default:
		return errors.New("\"" + decoy + "\" contains too many commas")
	}

	sni := splitDecoy[0]

	decoySpec := pb.InitTLSDecoySpec(ip, sni)
	tapdance.Assets().GetClientConfPtr().DecoyList =
		&pb.DecoyList{
			TlsDecoys: []*pb.TLSDecoySpec{
				decoySpec,
			},
		}
	tapdance.Logger().Infof("Single decoy parsed. SNI: %s, IP: %s", sni, ip)
	return nil
}
