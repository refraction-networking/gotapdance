package tapdance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/refraction-networking/conjure"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	pb "github.com/refraction-networking/conjure/proto"
)

var sessionsTotal CounterUint64
var randomizePortDefault = false

// Dialer contains options and implements advanced functions for establishing TapDance connection.
type Dialer struct {
	SplitFlows bool

	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	//
	// Deprecated: Dialer does not allow specifying the local address used for NAT traversal in
	// some transports. Use DialerWithLaddr instead.
	Dialer func(context.Context, string, string) (net.Conn, error)

	// DialerWithLaddr allows a custom dialer to be used for the underlying TCP/UDP connection.
	//
	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	DialerWithLaddr interfaces.DialFunc

	DarkDecoy bool

	// The type of registrar to use when performing Conjure registrations.
	DarkDecoyRegistrar Registrar

	// DisableRegistrarOverrides Indicates whether the client will allow the registrar to provide
	// alternative parameters that may work better in substitute for the deterministically selected
	// parameters. This only works for bidirectional registration methods where the client receives
	// a RegistrationResponse.
	DisableRegistrarOverrides bool

	// The type of transport to use for Conjure connections.
	Transport       *pb.TransportType
	TransportConfig interfaces.Transport

	// RegDelay is the delay duration to wait for registration ingest.
	RegDelay time.Duration

	UseProxyHeader bool
	V6Support      bool

	// Width indicates the number of independent decoy registrations to send in parallel as success
	// rates for individual decoy registrations are relatively low. (Default 5)
	//
	// Deprecated: Use the Width parameter in the Decoy Registrar.
	Width int

	// Subnet that we want to limit to (or empty if they're all fine)
	PhantomNet string
}

// Dial connects to the address on the named network.
//
// The only supported network at this time: "tcp".
// The address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// To avoid abuse, only certain whitelisted ports are allowed.
//
// Example: Dial("tcp", "golang.org:80")
func Dial(network, address string) (net.Conn, error) {
	var d Dialer
	return d.Dial(network, address)
}

// Dial connects to the address on the named network.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
// Long deadline is strongly advised, since tapdance will try multiple decoys.
//
// The only supported network at this time: "tcp".
// The address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// To avoid abuse, only certain whitelisted ports are allowed.
//
// Example: Dial("tcp", "golang.org:80")
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}
	if len(address) > 0 {
		_, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
	}

	if d.DialerWithLaddr != nil && d.Dialer != nil {
		return nil, fmt.Errorf("both DialerWithLaddr and Dialer are defined, only define DialerWithLaddr")
	}

	if d.Dialer != nil {
		d.DialerWithLaddr = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
			if laddr != "" {
				return nil, errUnsupportedLaddr
			}
			return d.Dialer(ctx, network, raddr)
		}
	}

	if d.DialerWithLaddr == nil {
		// custom dialer is not set, use default
		defaultDialer := net.Dialer{}
		dialMutex := sync.Mutex{}
		d.DialerWithLaddr = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
			localAddr, err := resolveAddr(network, laddr)
			if err != nil {
				return nil, fmt.Errorf("error resolving laddr: %v", err)
			}

			dialMutex.Lock()
			defer dialMutex.Unlock()

			defaultDialer.LocalAddr = localAddr

			return defaultDialer.DialContext(ctx, network, raddr)
		}
	}

	if !d.SplitFlows {
		if !d.DarkDecoy {
			flow, err := makeTdFlow(flowBidirectional, nil, address)
			if err != nil {
				return nil, err
			}
			flow.tdRaw.Dialer = d.Dialer
			flow.tdRaw.useProxyHeader = d.UseProxyHeader
			return flow, flow.DialContext(ctx)
		}

		var ipv conjure.IPSupport
		if d.V6Support {
			ipv = conjure.V6 | conjure.V4
		} else {
			ipv = conjure.V4
		}

		transport := d.TransportConfig
		var err error
		if d.TransportConfig == nil {
			transport, err = configFromTransportType(*d.Transport, randomizePortDefault)
		}
		if err != nil {
			return nil, err
		}

		cjDialer := conjure.Dialer{
			Transport:                 transport,
			Registrar:                 d.DarkDecoyRegistrar,
			DisableRegistrarOverrides: d.DisableRegistrarOverrides,
			UseProxyHeader:            d.UseProxyHeader,
			IPv:                       ipv,
			Dialer:                    d.Dialer,
			DialWithLaddr:             d.DialerWithLaddr,
			PhantomNet:                d.PhantomNet,
		}

		return cjDialer.DialContext(ctx, network, address)
	}

	return nil, errors.New("SplitFlows are not supported")
}

// DialProxy establishes direct connection to TapDance station proxy.
// Users are expected to send HTTP CONNECT request next.
func (d *Dialer) DialProxy() (net.Conn, error) {
	return d.DialProxyContext(context.Background())
}

// DialProxyContext establishes direct connection to TapDance station proxy using the provided context.
// Users are expected to send HTTP CONNECT request next.
func (d *Dialer) DialProxyContext(ctx context.Context) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", "")
}

func resolveAddr(network, addrStr string) (net.Addr, error) {
	if addrStr == "" {
		return nil, nil
	}

	if strings.Contains(network, "tcp") {
		return net.ResolveTCPAddr(network, addrStr)
	}

	return net.ResolveUDPAddr(network, addrStr)
}

var errUnsupportedLaddr = fmt.Errorf("dialer does not support laddr")

func configFromTransportType(transportType pb.TransportType, randomizeDst bool) (interfaces.Transport, error) {
	switch transportType {
	case pb.TransportType_Min:
		return &min.ClientTransport{Parameters: &pb.GenericTransportParams{RandomizeDstPort: &randomizePortDefault}}, nil
	case pb.TransportType_Obfs4:
		return &obfs4.ClientTransport{Parameters: &pb.GenericTransportParams{RandomizeDstPort: &randomizePortDefault}}, nil
	default:
		return nil, errors.New("unknown transport by TransportType try using TransportConfig")
	}
}
