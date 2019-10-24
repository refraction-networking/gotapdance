package tapdance

import (
	"context"
	"errors"
	"net"
)

var sessionsTotal CounterUint64

// Dialer contains options and implements advanced functions for establishing TapDance connection.
type Dialer struct {
	SplitFlows bool
	TcpDialer  func(context.Context, string, string) (net.Conn, error)

	DarkDecoy      bool
	UseProxyHeader bool
	V6Support      bool // *bool so that it is a nullable type. that can be overridden
	Width          int
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

	if !d.SplitFlows {
		if !d.DarkDecoy {
			flow, err := makeTdFlow(flowBidirectional, nil, address)
			if err != nil {
				return nil, err
			}
			flow.tdRaw.TcpDialer = d.TcpDialer
			return flow, flow.DialContext(ctx)
		} else {
			// _, err := makeTdFlow(flowBidirectional, nil, address)
			// if err != nil {
			// 	return nil, err
			// }
			cjSession := makeConjureSession(address)
			cjSession.UseProxyHeader = d.UseProxyHeader
			cjSession.Width = uint(d.Width)

			if d.V6Support {
				cjSession.V6Support = &V6{include: both, support: true}
			} else {
				cjSession.V6Support = &V6{include: v4, support: false}
			}
			if len(address) == 0 {
				return nil, errors.New("Dark Decoys require target address to be set")
			}
			return DialConjure(ctx, cjSession)
		}
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
