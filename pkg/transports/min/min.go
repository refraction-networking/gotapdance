package min

import (
	"fmt"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/refraction-networking/gotapdance/tapdance"
	"google.golang.org/protobuf/proto"
)

// Transport implements the client side transport interface for the Min transport
type Transport struct {
	// Parameters are fields that will be shared with the station in the registration
	Parameters *pb.GenericTransportParams

	// // state tracks fields internal to the registrar that survive for the lifetime
	// // of the transport session without being shared - i.e. local derived keys.
	// state any
}

// Name returns a string identifier for the Transport for logging
func (*Transport) Name() string {
	return "min"
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (*Transport) String() string {
	return "min"
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*Transport) ID() pb.TransportType {
	return pb.TransportType_Min
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *Transport) GetParams() proto.Message {
	return t.Parameters
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *Transport) SetParams(p any) error {
	params, ok := p.(*pb.GenericTransportParams)
	if !ok {
		return fmt.Errorf("unable to parse params")
	}
	t.Parameters = params

	return nil
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *Transport) GetDstPort(reg *tapdance.ConjureReg) uint16 {
	if t.Parameters == nil || !t.Parameters.GetRandomizeDstPort() {
		return 443
	}

	return 0
}

// // Connect creates the connection to the phantom address negotiated in the registration phase of
// // Conjure connection establishment.
// func (t *Transport) Connect(ctx context.Context, reg *cj.ConjureReg) (net.Conn, error) {
// 	// conn, err := reg.getFirstConnection(ctx, reg.TcpDialer, phantoms)
// 	// if err != nil {
// 	// 	return nil, err
// 	// }

// 	// // Send hmac(seed, str) bytes to indicate to station (min transport)
// 	// connectTag := conjureHMAC(reg.keys.SharedSecret, "MinTransportHMACString")
// 	// conn.Write(connectTag)
// 	// return conn, nil
// 	return nil, nil
// }
