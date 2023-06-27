package tapdance

import (
	"context"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
)

type Transport interfaces.Transport

// Registrar defines the interface for a service executing
// decoy registrations.
type Registrar interface {
	Register(*ConjureSession, context.Context) (*ConjureReg, error)
}
