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
	"strings"
)

func main() {
	defer profile.Start().Stop()

	var port = flag.Int("port", 10500, "TapDance will listen for connections on this port.")
	var decoy = flag.String("decoy", "", "Single decoy to use. Accepts \"SNI,IP\" or simply \"SNI\""+
		" — IP will be resolved. Examples: \"site.io,1.2.3.4\", \"site.io\"")
	var assets_location = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
	var proxyProtocol = flag.Bool("proxyproto", false, "Enable PROXY protocol, requesting TapDance station to send client's IP to destination.")
	flag.Parse()

	tapdance.AssetsSetDir(*assets_location)
	if *decoy != "" {
		err := setSingleDecoyHost(*decoy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set single decoy host: %s\n", err)
			flag.Usage()
			os.Exit(255)
		}
	}
	if *proxyProtocol {
		tapdance.EnableProxyProtocol()
	}

	tapdanceProxy := tdproxy.NewTapDanceProxy(*port)
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
