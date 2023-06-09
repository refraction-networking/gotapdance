package interfaces

import (
	"context"
	"io"
	"net"
	"sync"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"google.golang.org/protobuf/proto"
)

// Transport provides a generic interface for utilities that allow the client to dial and connect to
// a phantom address when creating a Conjure connection.
type Transport interface {
	// Name returns a string identifier for the Transport for logging
	Name() string
	// String returns a string identifier for the Transport for logging (including string formatters)
	String() string

	// // Connect creates the connection to the phantom address negotiated in the registration phase of
	// // Conjure connection establishment.
	// Connect(ctx context.Context, reg *ConjureReg) (net.Conn, error)

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

	// Prepare provides an opportunity for the transport to integrate the station public key
	// as well as bytes from the deterministic random generator associated with the registration
	// that this ClientTransport is attached to.
	Prepare(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error

	// Connect returns a net.Conn connection given a context and ConjureReg
	// Creates dependency on ConjureReg depends on tapdance depends on interfaces (move ConjureReg here or create new interface)
	Connect(ctx context.Context, reg *ConjureReg) (net.Conn, error)
}

type Obfs4Keys struct {
	PrivateKey *ntor.PrivateKey
	PublicKey  *ntor.PublicKey
	NodeID     *ntor.NodeID
}

type sharedKeys struct {
	SharedSecret, Representative                               []byte
	FspKey, FspIv, VspKey, VspIv, NewMasterSecret, ConjureSeed []byte
	Obfs4Keys                                                  Obfs4Keys
}

// Simple type alias for brevity
type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// ConjureReg - Registration structure created for each individual registration within a session.
type ConjureReg struct {
	Transport

	seed           []byte
	sessionIDStr   string
	phantom4       *net.IP
	phantom6       *net.IP
	phantomDstPort uint16
	useProxyHeader bool
	covertAddress  string
	phantomSNI     string
	v6Support      uint

	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	Dialer dialFunc

	stats *pb.SessionStats
	keys  *sharedKeys
	m     sync.Mutex
}
