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
	"sync"
	"time"

	"github.com/pkg/profile"
	"github.com/refraction-networking/gotapdance/pkg/registration"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/refraction-networking/gotapdance/tapdance/phantoms"
	"github.com/refraction-networking/gotapdance/tdproxy"
	"github.com/sirupsen/logrus"
)

const (
	defaultAPIEndpoint     = "https://registration.refraction.network/api/register"
	defaultBDAPIEndpoint   = "https://registration.refraction.network/api/register-bidirectional"
	defaultConnectionDelay = 750 * time.Millisecond
)

func main() {
	defer profile.Start().Stop()

	var port = flag.Int("port", 10500, "TapDance will listen for connections on this port.")
	var excludeV6 = flag.Bool("disable-ipv6", false, "Explicitly disable IPv6 decoys. Default(false): enable IPv6 only if interface with global IPv6 address is available.")
	var proxyHeader = flag.Bool("proxy", false, "Send the proxy header with all packets from station to covert host")
	var decoy = flag.String("decoy", "", "Sets single decoy. ClientConf won't be requested. "+
		"Accepts \"SNI,IP\" or simply \"SNI\" — IP will be resolved. "+
		"Examples: \"site.io,1.2.3.4\", \"site.io\"")
	var assets_location = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
	var width = flag.Int("w", 5, "Number of registrations sent for each connection initiated")
	var debug = flag.Bool("debug", false, "Enable debug level logs")
	var trace = flag.Bool("trace", false, "Enable trace level logs")
	var tlsLog = flag.String("tlslog", "", "Filename to write SSL secrets to (allows Wireshark to decrypt TLS connections)")
	var connect_target = flag.String("connect-addr", "", "If set, tapdance will transparently connect to provided address, which must be either hostname:port or ip:port. "+
		"Default(unset): connects client to forwardproxy, to which CONNECT request is yet to be written.")

	var td = flag.Bool("td", false, "Enable tapdance cli mode for compatibility")
	var APIRegistration = flag.String("api-endpoint", "", "If set, API endpoint to use when performing API registration. Defaults to https://registration.refraction.network/api/register (or register-bidirectional for bdapi)")
	var registrar = flag.String("registrar", "decoy", "One of decoy, api, bdapi, dns, bddns.")
	var transport = flag.String("transport", "min", `The transport to use for Conjure connections. Current values include "min" and "obfs4".`)

	var phantomNet = flag.String("phantom", "", "Target phantom subnet. Must overlap with ClientConf, and will be achieved by brute force of seeds until satisified")

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

	v6Support := !*excludeV6

	tapdance.AssetsSetDir(*assets_location)

	if *decoy != "" {
		err := setSingleDecoyHost(*decoy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set single decoy host: %s\n", err)
			flag.Usage()
			os.Exit(255)
		}
	}

	// Check that the provided phantom net overlaps with at least one of our phatom options
	if *phantomNet != "" {
		// Load phantoms
		subnets, err := phantoms.GetUnweightedSubnetList(tapdance.Assets().GetPhantomSubnets())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get Phantom subnets: %v\n", err)
			os.Exit(255)
		}

		// Check that the provided phantom parses as a CIDR range
		_, phantomRange, err := net.ParseCIDR(*phantomNet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing phantom subnet %s: %v\n", *phantomNet, err)
			flag.Usage()
			os.Exit(255)
		}

		// Iterate through all subnets, see if any overlap with the phantomRange
		found := false
		for _, subnet := range subnets {
			if subnet.Contains(phantomRange.IP) || phantomRange.Contains(subnet.IP) {
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: provided phantom net %v does not overlap with any phantoms in ClientConf\n", *phantomNet)
			os.Exit(255)
		}
	}

	if *debug {
		tapdance.Logger().Level = logrus.DebugLevel
		tapdance.Logger().Debug("Debug logging enabled")
	}
	if *trace {
		tapdance.Logger().Level = logrus.TraceLevel
		tapdance.Logger().Trace("Trace logging enabled")
	}

	if *tlsLog != "" {
		err := tapdance.SetTlsLogFilename(*tlsLog)
		if err != nil {
			tapdance.Logger().Fatal(err)
		}
	}

	if *td {
		fmt.Printf("Using Station Pubkey: %s\n", hex.EncodeToString(tapdance.Assets().GetPubkey()[:]))
	} else {
		fmt.Printf("Using Station Pubkey: %s\n", hex.EncodeToString(tapdance.Assets().GetConjurePubkey()[:]))
	}

	err := connectDirect(*td, *APIRegistration, *registrar, *connect_target, *port, *proxyHeader, v6Support, *width, *transport, *phantomNet)
	if err != nil {
		tapdance.Logger().Println(err)
		os.Exit(1)
	}

	// Dead code?
	/*
		tapdanceProxy := tdproxy.NewTapDanceProxy(*port)
		err = tapdanceProxy.ListenAndServe()
		if err != nil {
			tdproxy.Logger.Errorf("Failed to ListenAndServe(): %v\n", err)
			os.Exit(1)
		}*/
}

func connectDirect(td bool, apiEndpoint string, registrar string, connect_target string, localPort int, proxyHeader bool, v6Support bool, width int, transport string, phantomNet string) error {
	if _, _, err := net.SplitHostPort(connect_target); err != nil {
		return fmt.Errorf("failed to parse host and port from connect_target %s: %v",
			connect_target, err)
	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		return fmt.Errorf("error listening on port %v: %v", localPort, err)
	}

	tdDialer := tapdance.Dialer{
		DarkDecoy:          !td,
		DarkDecoyRegistrar: registration.NewDecoyRegistrar(),
		UseProxyHeader:     proxyHeader,
		V6Support:          v6Support,
		Width:              width,
		Transport:          getTransportFromName(transport),
		PhantomNet:         phantomNet,
	}

	switch registrar {
	case "decoy":
		tdDialer.DarkDecoyRegistrar = registration.NewDecoyRegistrar()
	case "api":
		if apiEndpoint == "" {
			apiEndpoint = defaultAPIEndpoint
		}
		tdDialer.DarkDecoyRegistrar, err = registration.NewAPIRegistrar(apiEndpoint, nil, false, defaultConnectionDelay, 3, registration.NewDecoyRegistrar())
		if err != nil {
			return fmt.Errorf("error creating API registrar: %w", err)
		}
	case "bdapi":
		if apiEndpoint == "" {
			apiEndpoint = defaultBDAPIEndpoint
		}
		tdDialer.DarkDecoyRegistrar, err = registration.NewAPIRegistrar(apiEndpoint, nil, true, defaultConnectionDelay, 3, registration.NewDecoyRegistrar())
		if err != nil {
			return fmt.Errorf("error creating API registrar: %w", err)
		}
	case "dns":
		dnsConf := tapdance.Assets().GetDNSRegConf()
		tdDialer.DarkDecoyRegistrar, err = registration.NewDNSRegistrarFromConf(dnsConf, false, defaultConnectionDelay, 3, tapdance.Assets().GetConjurePubkey()[:])
		if err != nil {
			return fmt.Errorf("error creating DNS registrar: %w", err)
		}
	case "bddns":
		dnsConf := tapdance.Assets().GetDNSRegConf()
		tdDialer.DarkDecoyRegistrar, err = registration.NewDNSRegistrarFromConf(dnsConf, true, defaultConnectionDelay, 3, tapdance.Assets().GetConjurePubkey()[:])
		if err != nil {
			return fmt.Errorf("error creating DNS registrar: %w", err)
		}
	default:
		return fmt.Errorf("unknown registrar %v", registrar)
	}

	for {
		clientConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("error accepting client connection %v: ", err)
		}

		go manageConn(tdDialer, connect_target, clientConn)
	}
}

func manageConn(tdDialer tapdance.Dialer, connect_target string, clientConn *net.TCPConn) {
	// TODO: go back to pre-dialing after measuring performance
	tdConn, err := tdDialer.Dial("tcp", connect_target)
	if err != nil || tdConn == nil {
		fmt.Errorf("failed to dial %s: %v", connect_target, err)
		return
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

func getTransportFromName(name string) pb.TransportType {
	switch name {
	case "min":
		return pb.TransportType_Min
	case "obfs4":
		return pb.TransportType_Obfs4
	default:
		return pb.TransportType_Min
	}
}
