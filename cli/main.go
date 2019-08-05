package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/pkg/profile"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
	"github.com/sirupsen/logrus"
)

func main() {
	defer profile.Start().Stop()

	var port = flag.Int("port", 10500, "TapDance will listen for connections on this port.")
	var decoy = flag.String("decoy", "", "Sets single decoy. ClientConf won't be requested. "+
		"Accepts \"SNI,IP\" or simply \n\"SNI\" — IP will be resolved. "+
		"\nExamples: \"site.io,1.2.3.4\", \"site.io\"")
	var assets_location = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
	var proxyProtocol = flag.Uint("proxyproto", 1, "Specify PROXY protocol, requesting TapDance station to send client's IP to \ndestination. Used when connecting to followup proxy after.")
	var debug = flag.Bool("debug", false, "Enable debug logs")
	var tlsLog = flag.String("tlslog", "", "Filename to write SSL secrets to (allows Wireshark to decrypt TLS connections)")
	var connect_target = flag.String("connect-addr", "", "If set, tapdance will transparently connect to provided address, which \nmust be either hostname:port or ip:port. "+
		"Default(unset): connects client to \nforwardproxy, to which CONNECT request is yet to be written.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Dark Decoy CLI\n$./cli -connect-addr=<decoy_address> [OPTIONS] \n\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *connect_target == "" {
		tdproxy.Logger.Errorf("dark decoys require -connect-addr to be set\n")
		flag.Usage()

		os.Exit(1)
	}

	if *debug {
		tapdance.Logger().Level = logrus.DebugLevel
	}
	tapdance.Logger().Debug("Debug logging enabled")

	tapdance.AssetsSetDir(*assets_location)
	if *decoy != "" {
		err := setSingleDecoyHost(*decoy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set single decoy host: %s\n", err)
			flag.Usage()
			os.Exit(255)
		}
	}

	err := tapdance.EnableProxyProtocol(*proxyProtocol)
	if err != nil {

	}

	if *tlsLog != "" {
		err := tapdance.SetTlsLogFilename(*tlsLog)
		if err != nil {
			tapdance.Logger().Fatal(err)
		}
	}

	tapdance.Logger().Debugf("STATION_PUBKEY\n%s", hex.Dump((*(tapdance.Assets().GetPubkey()))[:]))

	err = connectDirect(*connect_target, *port)
	if err != nil {
		tapdance.Logger().Println(err)
		os.Exit(1)
	}

	tapdanceProxy := tdproxy.NewTapDanceProxy(*port)
	err = tapdanceProxy.ListenAndServe()
	if err != nil {
		tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
		os.Exit(1)
	}
}

func connectDirect(connect_target string, localPort int) error {
	if _, _, err := net.SplitHostPort(connect_target); err != nil {
		return fmt.Errorf("failed to parse host and port from connect_target %s: %v",
			connect_target, err)
		os.Exit(1)
	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		return fmt.Errorf("error listening on port %s: %v", localPort, err)
	}

	tdDialer := tapdance.Dialer{DarkDecoy: true}
	for {
		clientConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("error accepting client connection %v: ", err)
		}
		// TODO: go back to pre-dialing after measuring performance
		tdConn, err := tdDialer.Dial("tcp", connect_target)
		if err != nil {
			return fmt.Errorf("failed to dial %s: %v", connect_target, err)
		}
		// TODO: proper connection management with idle timeout
		go func() {
			io.Copy(tdConn, clientConn)
			tdConn.Close()
		}()
		go func() {
			io.Copy(clientConn, tdConn)
			clientConn.CloseWrite()
		}()
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
	maxUint32 := ^uint32(0) // max generation: station won't send ClientConf
	tapdance.Assets().GetClientConfPtr().Generation = &maxUint32
	tapdance.Logger().Infof("Single decoy parsed. SNI: %s, IP: %s", sni, ip)
	return nil
}
