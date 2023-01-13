package transports

import (
	"errors"

	"github.com/refraction-networking/conjure/application/transports/wrapping/min"
	"github.com/refraction-networking/conjure/application/transports/wrapping/obfs4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	cj "github.com/refraction-networking/gotapdance/tapdance"
)

var transportsByName map[string]cj.Transport = make(map[string]cj.Transport)
var transportsByID map[pb.TransportType]cj.Transport = make(map[pb.TransportType]cj.Transport)

var (
	// ErrAlreadyRegistered error when registering a transport that matches
	// an already registered ID or name.
	ErrAlreadyRegistered = errors.New("transport already registered")

	// ErrUnknownTransport provided id or name does npt match any enabled
	// transport.
	ErrUnknownTransport = errors.New("unknown transport")
)

// New returns a new Transport
func New(name string) (cj.Transport, error) {
	transport, ok := transportsByName[name]
	if !ok {
		return nil, ErrUnknownTransport
	}

	return transport, nil
}

// NewWithParams returns a new Transport and attempts to set the parameters provided
func NewWithParams(name string, params any) (cj.Transport, error) {
	transport, ok := transportsByName[name]
	if !ok {
		return nil, ErrUnknownTransport
	}

	err := transport.SetParams(params)
	return transport, err
}

// GetTransportByName returns transport by name
func GetTransportByName(name string) (cj.Transport, bool) {
	t, ok := transportsByName[name]
	return t, ok
}

// GetTransportByID returns transport by name
func GetTransportByID(id pb.TransportType) (cj.Transport, bool) {
	t, ok := transportsByID[id]
	return t, ok
}

var defaultTransports = []cj.Transport{
	&min.ClientTransport{},
	&obfs4.ClientTransport{},
}

// AddTransport adds new transport
func AddTransport(t cj.Transport) error {
	name := t.Name()
	id := t.ID()

	if _, ok := transportsByName[name]; ok {
		return ErrAlreadyRegistered
	} else if _, ok := transportsByID[id]; ok {
		return ErrAlreadyRegistered
	}

	transportsByName[name] = t
	transportsByID[id] = t
	return nil
}

// EnableDefaultTransports initializes the library with default transports
func EnableDefaultTransports() error {
	var err error
	for _, t := range defaultTransports {
		err = AddTransport(t)
		if err != nil {
			return err
		}
	}

	return nil
}

// func init() {
// 	EnableDefaultTransports()
// }
