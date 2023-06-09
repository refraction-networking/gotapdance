package tapdance

import (
	"context"

	"github.com/refraction-networking/gotapdance/pkg/interfaces"
)

type Transport interfaces.Transport

// Registrar defines the interface for a service executing
// decoy registrations.
type Registrar interface {
	Register(*ConjureSession, context.Context) (*ConjureReg, error)
}

// // Transport provides a generic interface for utilities that allow the client to dial and connect to
// // a phantom address when creating a Conjure connection.
// type Transport interface {
// 	// Name returns a string identifier for the Transport for logging
// 	Name() string
// 	// String returns a string identifier for the Transport for logging (including string formatters)
// 	String() string

// 	// // Connect creates the connection to the phantom address negotiated in the registration phase of
// 	// // Conjure connection establishment.
// 	// Connect(ctx context.Context, reg *ConjureReg) (net.Conn, error)

// 	// ID provides an identifier that will be sent to the conjure station during the registration so
// 	// that the station knows what transport to expect connecting to the chosen phantom.
// 	ID() pb.TransportType

// 	// GetParams returns a generic protobuf with any parameters from both the registration and the
// 	// transport.
// 	GetParams() proto.Message

// 	// SetParams allows the caller to set parameters associated with the transport, returning an
// 	// error if the provided generic message is not compatible.
// 	SetParams(any) error

// 	// GetDstPort returns the destination port that the client should open the phantom connection with.
// 	GetDstPort(seed []byte, params any) (uint16, error)
// }
