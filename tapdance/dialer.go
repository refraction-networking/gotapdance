package tapdance

import (
	"net"
)

/*
// It provides a way to make outgoing transport connections and to accept
// incoming transport connections.
// It also exposes access to an underlying network connection Dialer.
// The Dialer can be modified to change how the network connections are made.
// The Transport interface implements the Transport​ abstract interface.
type Transport interface {
	//Note that there is no place in this interface to provide the
	//transport configuration​. This is provided in the initializer function
	//for the instance of the Transport interface and so is not included in
	//the interface definition.
	//Dialer for the underlying network connection
	NetworkDialer() net.Dialer

	// Create outgoing transport connection
	// The Dial method implements the Client Factory ​abstract interface.

	Dial(address string) TransportConn

	// Create listener for incoming transport connection
	// The Listen method implements the Server Factory ​abstract interface.

	Listen(address string) TransportListener
}
*/
var sessionsTotal CounterUint64

type Dialer struct {
	// TODO: add Context support(not as a field, it has to "flow through program like river")
	// https://medium.com/@cep21/how-to-correctly-use-context-context-in-go-1-7-8f2c0fafdf39
	// TODO: add various modes, e.g. non read flows and other dialing options
	// TODO: include a factory of raw async TapDance connections that can be used on demand?
	tcpDialer func(string, string) (net.Conn, error)
}

// TODO: add following functions:
//  * func Dial(network, address string) (Conn, error)
//  * func DialWithCustomDialer(network, address string, customDialer func(string, string) (net.Conn, error)) (Conn, error) ?
// which would set up proxy to target website _directly_

func DialSOCKSWithCustomDialer(customDialer func(string, string) (net.Conn, error)) (net.Conn, error) {
	var d Dialer
	d.tcpDialer = customDialer
	return d.DialSOCKS()
}

func Dial(address string) TransportConn {
	var d Dialer
	conn, err := d.Dial(address)
	if err != nil {
		// log error
		return nil
	}
	return conn
}

func (d *Dialer) Dial(address string) (TransportConn, error) {
	// TODO: Dialer probably should implement net.Dialer and not Transport
	panic("Not implemented")
}

// Does not connect directly, users are expected to do CONNECT HTTP request
func DialSOCKS() (net.Conn, error) {
	var d Dialer
	return d.DialSOCKS()
}

func (d *Dialer) DialSOCKS() (net.Conn, error) {
	return dialBidirectional(d.tcpDialer, sessionsTotal.GetAndInc())
}

func (d *Dialer) DialSOCKSSplitFlow() (net.Conn, error) {
	return dialSplitFlow(d.tcpDialer, sessionsTotal.GetAndInc())
}
