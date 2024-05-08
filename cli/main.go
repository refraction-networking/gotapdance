package main

import (
	"context"
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
	ca "github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/phantoms"
	decoyreg "github.com/refraction-networking/conjure/pkg/registrars/decoy-registrar"
	"github.com/refraction-networking/conjure/pkg/registrars/registration"
	"github.com/refraction-networking/conjure/pkg/station/oscur0"
	transports "github.com/refraction-networking/conjure/pkg/transports/client"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/refraction-networking/gotapdance/tdproxy"
	"github.com/sirupsen/logrus"
)

const oscur0_test_pubkey = "8c34e2362f33707ff4b001f31302b1968fe8d67fb8843ee11c60df61b9e17609"

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
	var assetsLocation = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
	var width = flag.Int("w", 5, "Number of registrations sent for each connection initiated")
	var debug = flag.Bool("debug", false, "Enable debug level logs")
	var trace = flag.Bool("trace", false, "Enable trace level logs")
	var tlsLog = flag.String("tlslog", "", "Filename to write SSL secrets to (allows Wireshark to decrypt TLS connections)")
	var connectTarget = flag.String("connect-addr", "", "If set, tapdance will transparently connect to provided address, which must be either hostname:port or ip:port. "+
		"Default(unset): connects client to forwardproxy, to which CONNECT request is yet to be written.")

	var td = flag.Bool("td", false, "Enable tapdance cli mode for compatibility")
	var APIRegistration = flag.String("api-endpoint", "", "If set, API endpoint to use when performing API registration. Defaults to https://registration.refraction.network/api/register (or register-bidirectional for bdapi)")
	var registrar = flag.String("registrar", "decoy", "One of decoy, api, bdapi, dns, bddns.")
	var transport = flag.String("transport", "min", `The transport to use for Conjure connections. Current values include "prefix", "min" and "obfs4".`)
	var randomizeDstPort = flag.Bool("rand-dst-port", false, `enable destination port randomization for the transport connection`)
	var prefixID = flag.Int("prefix-id", -1, "ID of the prefix to send, used with the `transport=\"prefix\"` option. Default is Random. See prefix transport for options")
	var disableOverrides = flag.Bool("disable-overrides", false, "Informs the registrar that chosen parameters will be used, only applicable to bidirectional reg methods")
	var phantomNet = flag.String("phantom", "", "Target phantom subnet. Must overlap with ClientConf, and will be achieved by brute force of seeds until satisfied")
	var registerOnly = flag.Bool("register-only", false, "register to use a phantom, but do not connect to a covert. Only works with \"bdapi\" registrar")
	var dtlsUnordered = flag.Bool("unordered-dtls", false, "Set DTLS reliability to unordered. Only works with DTLS transport.")
	var oscur0 = flag.Bool("oscur0", false, "Use oscur0.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Dark Decoy CLI\n$./cli -connect-addr=<decoy_address> [OPTIONS] \n\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *oscur0 {
		err := connectOscur0(*connectTarget, *port, *phantomNet)
		if err != nil {
			tapdance.Logger().Println(err)
			os.Exit(1)
		}
	}

	if !*registerOnly {
		if *connectTarget == "" {
			tdproxy.Logger.Errorf("dark decoys require -connect-addr to be set\n")
			flag.Usage()

			os.Exit(1)
		}
	} else {
		// since this is a registration-only run, use a dummy target that we will never connect to
		*connectTarget = "refraction.network:443"

		// always disable registrar overrides when register-only option is set. Only applicable to bidirectional registration
		*disableOverrides = true

		if *phantomNet == "" {
			tdproxy.Logger.Errorf("register-only option requires -phantom to be set \n")
			flag.Usage()

			os.Exit(1)

		}
	}

	v6Support := !*excludeV6

	_, err := ca.AssetsSetDir(*assetsLocation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse assets: %s", err)
		os.Exit(1)
	}

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
		subnets, err := phantoms.GetUnweightedSubnetList(ca.Assets().GetPhantomSubnets())
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
		fmt.Printf("Using Station Pubkey: %s\n", hex.EncodeToString(ca.Assets().GetPubkey()[:]))
	} else {
		fmt.Printf("Using Station Pubkey: %s\n", hex.EncodeToString(ca.Assets().GetConjurePubkey()[:]))
	}

	var params any
	var t tapdance.Transport
	switch *transport {
	case "prefix":
		pID := int32(*prefixID)
		params = &pb.PrefixTransportParams{RandomizeDstPort: randomizeDstPort, PrefixId: &pID}
	case "dtls":
		params = &pb.DTLSTransportParams{RandomizeDstPort: randomizeDstPort, Unordered: dtlsUnordered}
	default:
		params = &pb.GenericTransportParams{RandomizeDstPort: randomizeDstPort}
	}

	t, err = transports.NewWithParams(*transport, params)
	if err != nil {
		e := fmt.Errorf("error finding or creating transport %v: %v", *transport, err)
		tapdance.Logger().Println(e)
		os.Exit(1)
	}

	if *registerOnly {
		err = register(*td, *APIRegistration, *registrar, *connectTarget, *proxyHeader, v6Support, *width, t, *disableOverrides, *phantomNet, *registerOnly)
		if err != nil {
			tapdance.Logger().Println(err)
			os.Exit(1)
		}
	} else {
		err = connectDirect(*td, *APIRegistration, *registrar, *connectTarget, *port, *proxyHeader, v6Support, *width, t, *disableOverrides, *phantomNet, *registerOnly)
		if err != nil {
			tapdance.Logger().Println(err)
			os.Exit(1)
		}
	}
}

func register(td bool, apiEndpoint string, registrar string, dummyConnectTarget string, proxyHeader bool, v6Support bool, width int, t tapdance.Transport, disableOverrides bool, phantomNet string, registerOnly bool) error {
	tdDialer, err := prepareDialer(td, apiEndpoint, registrar, proxyHeader, v6Support, width, t, disableOverrides, phantomNet, registerOnly)
	if err != nil {
		return fmt.Errorf("error preparing tapdance Dialer: %w", err)
	}
	_, err = tdDialer.Dial("tcp", dummyConnectTarget)
	if err != nil {
		tapdance.Logger().Errorf("failed to register %s: %v\n", dummyConnectTarget, err)
	}
	return nil
}

func connectDirect(td bool, apiEndpoint string, registrar string, connectTarget string, localPort int, proxyHeader bool, v6Support bool, width int, t tapdance.Transport, disableOverrides bool, phantomNet string, registerOnly bool) error {
	if _, _, err := net.SplitHostPort(connectTarget); err != nil {
		return fmt.Errorf("failed to parse host and port from connectTarget %s: %v",
			connectTarget, err)

	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		return fmt.Errorf("error listening on port %v: %v", localPort, err)
	}

	tdDialer, err := prepareDialer(td, apiEndpoint, registrar, proxyHeader, v6Support, width, t, disableOverrides, phantomNet, registerOnly)
	if err != nil {
		return fmt.Errorf("error preparing tapdance Dialer: %w", err)
	}

	for {
		clientConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("error accepting client connection %v: ", err)
		}

		go manageConn(tdDialer, connectTarget, clientConn)
	}
}

func connectOscur0(connectTarget string, localPort int, phantomNet string) error {
	if _, _, err := net.SplitHostPort(connectTarget); err != nil {
		return fmt.Errorf("failed to parse host and port from connectTarget %s: %v",
			connectTarget, err)

	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		return fmt.Errorf("error listening on port %v: %v", localPort, err)
	}

	pubKey, err := hex.DecodeString(oscur0_test_pubkey)
	if err != nil {
		return err
	}

	keys, err := core.GenerateClientSharedKeys([32]byte(pubKey))
	if err != nil {
		return fmt.Errorf("error generating client keys: %v", err)
	}

	addr4, _, _, err := tapdance.SelectPhantom(keys.ConjureSeed, 0)
	if err != nil {
		return fmt.Errorf("error generating phantom address: %v", err)
	}

	testAddr := &net.UDPAddr{Port: 37421, IP: *addr4}

	pconn, err := net.ListenUDP("udp", nil)

	tdConn, err := oscur0.ClientWithContext(context.Background(), pconn, testAddr, oscur0.Config{Phantom: connectTarget, Keys: keys})

	clientConn, err := l.AcceptTCP()

	proxy(tdConn, clientConn)

	return nil
}

func manageConn(tdDialer tapdance.Dialer, connectTarget string, clientConn *net.TCPConn) {
	defer clientConn.Close()

	p, err := tdDialer.TransportConfig.GetParams()
	if err != nil {
		tapdance.Logger().Errorf("failed to get transport params: %v\n", err)
		return
	}
	tapdance.Logger().Debugf("transport: %s - %s - gen-%d\n", tdDialer.TransportConfig.String(), p, ca.Assets().GetGeneration())

	tdConn, err := tdDialer.Dial("tcp", connectTarget)
	if err != nil || tdConn == nil {
		tapdance.Logger().Errorf("failed to dial %s: %v\n", connectTarget, err)
		return
	}

	proxy(tdConn, clientConn)
}

func proxy(tdConn net.Conn, clientConn *net.TCPConn) {
	// Copy data from the client application into the DarkDecoy connection.
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
	ca.Assets().GetClientConfPtr().DecoyList =
		&pb.DecoyList{
			TlsDecoys: []*pb.TLSDecoySpec{
				decoySpec,
			},
		}
	tapdance.Logger().Infof("Single decoy parsed. SNI: %s, IP: %s", sni, ip)
	return nil
}

func prepareDialer(td bool, apiEndpoint string, registrar string, proxyHeader bool, v6Support bool, width int, t tapdance.Transport, disableOverrides bool, phantomNet string, registerOnly bool) (tapdance.Dialer, error) {

	tdDialer := tapdance.Dialer{
		DarkDecoy:          !td,
		DarkDecoyRegistrar: decoyreg.NewDecoyRegistrar(),
		UseProxyHeader:     proxyHeader,
		V6Support:          v6Support,
		Width:              width,
		RegDelay:           defaultConnectionDelay,
		// Transport:          			getTransportFromName(transport), // Still works for backwards compatibility
		TransportConfig:           t,
		PhantomNet:                phantomNet,
		DisableRegistrarOverrides: disableOverrides,
		RegisterOnly:              registerOnly,
	}

	var err error

	switch registrar {
	case "decoy":
		dr := decoyreg.NewDecoyRegistrar()
		dr.Width = uint(width)
		tdDialer.DarkDecoyRegistrar = dr
	case "api":
		if apiEndpoint == "" {
			apiEndpoint = defaultAPIEndpoint
		}
		tdDialer.DarkDecoyRegistrar, err = registration.NewAPIRegistrar(&registration.Config{
			Target:             apiEndpoint,
			Bidirectional:      false,
			MaxRetries:         3,
			SecondaryRegistrar: decoyreg.NewDecoyRegistrar(),
		})
		if err != nil {
			return tdDialer, fmt.Errorf("error creating API registrar: %w", err)
		}
	case "bdapi":
		if apiEndpoint == "" {
			apiEndpoint = defaultBDAPIEndpoint
		}
		tdDialer.DarkDecoyRegistrar, err = registration.NewAPIRegistrar(&registration.Config{
			Target:             apiEndpoint,
			Bidirectional:      true,
			MaxRetries:         3,
			SecondaryRegistrar: decoyreg.NewDecoyRegistrar(),
		})
		if err != nil {
			return tdDialer, fmt.Errorf("error creating API registrar: %w", err)
		}
	case "dns":
		dnsConf := ca.Assets().GetDNSRegConf()
		tdDialer.DarkDecoyRegistrar, err = newDNSRegistrarFromConf(dnsConf, false, 3, ca.Assets().GetConjurePubkey()[:])
		if err != nil {
			return tdDialer, fmt.Errorf("error creating DNS registrar: %w", err)
		}
	case "bddns":
		dnsConf := ca.Assets().GetDNSRegConf()
		tdDialer.DarkDecoyRegistrar, err = newDNSRegistrarFromConf(dnsConf, true, 3, ca.Assets().GetConjurePubkey()[:])
		if err != nil {
			return tdDialer, fmt.Errorf("error creating DNS registrar: %w", err)
		}
	default:
		return tdDialer, fmt.Errorf("unknown registrar %v", registrar)
	}
	return tdDialer, nil
}

// NewDNSRegistrarFromConf creates a DNSRegistrar from DnsRegConf protobuf. Uses the pubkey in conf as default. If it is not supplied (nil), uses fallbackKey instead.
func newDNSRegistrarFromConf(conf *pb.DnsRegConf, bidirectional bool, maxTries int, fallbackKey []byte) (*registration.DNSRegistrar, error) {
	pubkey := conf.Pubkey
	if pubkey == nil {
		pubkey = fallbackKey
	}
	var method registration.DNSTransportMethodType
	switch *conf.DnsRegMethod {
	case pb.DnsRegMethod_UDP:
		method = registration.UDP
	case pb.DnsRegMethod_DOT:
		method = registration.DoT
	case pb.DnsRegMethod_DOH:
		method = registration.DoH
	default:
		return nil, errors.New("unknown reg method in conf")
	}

	return registration.NewDNSRegistrar(&registration.Config{
		DNSTransportMethod: method,
		Target:             *conf.Target,
		BaseDomain:         *conf.Domain,
		Pubkey:             pubkey,
		UTLSDistribution:   *conf.UtlsDistribution,
		MaxRetries:         maxTries,
		Bidirectional:      bidirectional,
		STUNAddr:           *conf.StunServer,
	})
}

func getTransportFromName(name string) pb.TransportType {
	switch name {
	case "min":
		return pb.TransportType_Min
	case "obfs4":
		return pb.TransportType_Obfs4
	default:
		return pb.TransportType_Null
	}
}
