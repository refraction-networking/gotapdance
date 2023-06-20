package interfaces

import (
	"io"
	"net"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

// Transport provides a generic interface for utilities that allow the client to dial and connect to
// a phantom address when creating a Conjure connection.
type Transport interface {
	// Name returns a string identifier for the Transport for logging
	Name() string
	// String returns a string identifier for the Transport for logging (including string formatters)
	String() string

	// ID provides an identifier that will be sent to the conjure station during the registration so
	// that the station knows what transport to expect connecting to the chosen phantom.
	ID() pb.TransportType

	// GetParams returns a generic protobuf with any parameters from both the registration and the
	// transport.
	GetParams() proto.Message

	// SetParams allows the caller to set parameters associated with the transport, returning an
	// error if the provided generic message is not compatible.
	SetParams(any) error

	// GetDstPort returns the destination port that the client should open the phantom connection with.
	GetDstPort(seed []byte, params any) (uint16, error)

	// PrepareKeys provides an opportunity for the transport to integrate the station public key
	// as well as bytes from the deterministic random generator associated with the registration
	// that this ClientTransport is attached to.
	PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error

	// Connect returns a net.Conn connection given a context and ConjureReg
	WrapConn(conn net.Conn) (net.Conn, error)
}
