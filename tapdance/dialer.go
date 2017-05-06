package tapdance

import (
	"net"
)

var sessionsTotal CounterUint64

type Dialer struct {
	// TODO: add Context support(not as a field, it has to "flow through program like river")
	// https://medium.com/@cep21/how-to-correctly-use-context-context-in-go-1-7-8f2c0fafdf39
	// TODO: add various modes, e.g. non read flows and other dialing options
	// TODO: include a factory of raw async TapDance connections that can be used on demand?
	customDialer func(string, string) (net.Conn, error)
}

// TODO: add following functions:
//  * func Dial(network, address string) (Conn, error)
//  * func DialWithCustomDialer(network, address string, customDialer func(string, string) (net.Conn, error)) (Conn, error) ?
// which would set up proxy to target website _directly_

func DialSOCKSWithCustomDialer(customDialer func(string, string) (net.Conn, error)) (net.Conn, error) {
	var d Dialer
	d.customDialer = customDialer
	return d.DialSOCKS()
}

// Does not connect directly, users are expected to do CONNECT HTTP request
func DialSOCKS() (net.Conn, error) {
	var d Dialer
	return d.DialSOCKS()
}

func (d *Dialer) DialSOCKS() (net.Conn, error) {
	return doDialTDConn(d.customDialer, sessionsTotal.GetAndInc())
}
