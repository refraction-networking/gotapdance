package tapdance

import (
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
)

// Transport provides a generic interface for utilities that allow the client to dial and connect to
// a phantom address when creating a Conjure connection.
type Transport interfaces.Transport

// Registrar defines the interface for a service executing
type Registrar interfaces.Registrar

// // decoy registrations.
// type Registrar interface {
// 	Register(*ConjureSession, context.Context) (*ConjureReg, error)

// 	// PrepareRegKeys prepares key materials specific to the registrar
// 	PrepareRegKeys(pubkey [32]byte) error
// }
