package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pkg/profile"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/refraction-networking/gotapdance/tdproxy"
	"github.com/sirupsen/logrus"
)

func main() {
	defer profile.Start().Stop()

	var port = flag.Int("port", 10500, "TapDance will listen for connections on this port.")
	var excludeV6 = flag.Bool("e6", false, "Exclude Ipv6 blocks in decoy Ip selection - bypass getifaddr. (default false)")
	var includeV6 = flag.Bool("i6", false, "Include Ipv6 blocks in decoy Ip selection - bypass getifaddr. (default false)")
	var proxyHeader = flag.Bool("proxy", false, "Send the proxy header with all packets from station to covert host")
	var decoy = flag.String("decoy", "", "Sets single decoy. ClientConf won't be requested. "+
		"Accepts \"SNI,IP\" or simply \n\"SNI\" — IP will be resolved. "+
		"\nExamples: \"site.io,1.2.3.4\", \"site.io\"")
	var assets_location = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
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

	v6Support := v6_flags(includeV6, excludeV6)

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

	if *tlsLog != "" {
		err := tapdance.SetTlsLogFilename(*tlsLog)
		if err != nil {
			tapdance.Logger().Fatal(err)
		}
	}

	err := connectDirect(*connect_target, *port, *proxyHeader, v6Support)
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

func connectDirect(connect_target string, localPort int, proxyHeader bool, v6Support *bool) error {
	if _, _, err := net.SplitHostPort(connect_target); err != nil {
		return fmt.Errorf("failed to parse host and port from connect_target %s: %v",
			connect_target, err)
		os.Exit(1)
	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		return fmt.Errorf("error listening on port %v: %v", localPort, err)
	}

	tdDialer := tapdance.Dialer{DarkDecoy: true, UseProxyHeader: proxyHeader, V6Support: v6Support}

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

		// Copy data from the client application into the DarkDecoy connection.
		// 		TODO: Make sure this works
		// 		TODO: proper connection management with idle timeout
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			io.Copy(tdConn, clientConn)
			wg.Done()
			tdConn.Close()
		}()
		go func() {
			io.Copy(clientConn, tdConn)
			wg.Done()
			clientConn.CloseWrite()
		}()
		wg.Wait()
		tapdance.Logger().Debug("copy loop ended")
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

func v6_flags(includeV6, excludeV6 *bool) *bool {
	// Use *bool for nullable var as third option
	var holdTrue = true
	var holdFalse = false

	// Determine whether to Include / Exclude Ipv6 Blocks explicity or use getifaddr
	if *includeV6 != *excludeV6 {
		if *includeV6 {
			return &holdTrue
		} else {
			return &holdFalse
		}
	} else {
		if *includeV6 && *excludeV6 {
			tdproxy.Logger.Errorf("Cannot include and exclude v6 blocks in Ip selection\n")
			flag.Usage()
			os.Exit(1)
		} else {
			return nil
		}
	}
	return nil
}
