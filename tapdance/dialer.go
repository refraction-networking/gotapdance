package tapdance

import (
	"context"
	"errors"
	"net"

	transports "github.com/refraction-networking/conjure/pkg/transports/client"
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
	Dialer func(context.Context, string, string) (net.Conn, error)

	DarkDecoy bool

	// The type of registrar to use when performing Conjure registrations.
	DarkDecoyRegistrar Registrar

	// DisableRegistrarOverrides Indicates whether the client will allow the registrar to provide
	// alternative parameters that may work better in substitute for the deterministically selected
	// parameters. This only works for bidirectional registration methods where the client receives
	// a RegistrationResponse.
	DisableRegistrarOverrides bool

	// The type of transport to use for Conjure connections.
	Transport       pb.TransportType
	TransportConfig Transport

	UseProxyHeader bool
	V6Support      bool
	Width          int

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

	if d.Dialer == nil {
		// custom dialer is not set, use default
		defaultDialer := net.Dialer{}
		d.Dialer = defaultDialer.DialContext
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
		// Conjure
		var cjSession *ConjureSession

		transport := d.TransportConfig
		var err error
		if d.TransportConfig == nil {
			transport, err = transports.ConfigFromTransportType(d.Transport, randomizePortDefault)
		}
		if err != nil {
			return nil, err
		}

		// If specified, only select a phantom from a given range
		if d.PhantomNet != "" {
			_, phantomRange, err := net.ParseCIDR(d.PhantomNet)
			if err != nil {
				return nil, errors.New("Invalid Phantom network goal")
			}
			cjSession = FindConjureSessionInRange(address, d.TransportConfig, phantomRange)
			if cjSession == nil {
				return nil, errors.New("Failed to find Phantom in target subnet")
			}
		} else {
			cjSession = MakeConjureSession(address, transport)
		}

		cjSession.Dialer = d.Dialer
		cjSession.UseProxyHeader = d.UseProxyHeader
		cjSession.Width = uint(d.Width)
		cjSession.DisableRegistrarOverrides = d.DisableRegistrarOverrides

		if d.V6Support {
			cjSession.V6Support = &V6{include: both, support: true}
		} else {
			cjSession.V6Support = &V6{include: v4, support: false}
		}
		if len(address) == 0 {
			return nil, errors.New("Dark Decoys require target address to be set")
		}
		return DialConjure(ctx, cjSession, d.DarkDecoyRegistrar)
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
