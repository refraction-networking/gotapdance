package tapdance

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	// consider moving to ClientConf
	apiEndpoint         = "https://registration.refraction.network/api/register"
	bdApiEndpoint       = "https://registration.refraction.network/api/register-bidirectional"
	connectionDelay     = 750 * time.Millisecond
	retriesPerRegistrar = 1
)

// AutoRegistrar stores multiple registrars and calls each until a success
type AutoRegistrar struct {
	registrars []Registrar
}

// NewAutoRegistrar creates an AutoRegistrar from configuration stored in assets
func NewAutoRegistrar() (*AutoRegistrar, error) {
	registrars := []Registrar{}
	registrars = append(registrars, DecoyRegistrar{})

	registrars = append(registrars, APIRegistrarBidirectional{
		Endpoint:        bdApiEndpoint,
		ConnectionDelay: connectionDelay,
		MaxRetries:      retriesPerRegistrar,
	})

	dnsConf := Assets().GetDNSRegConf()
	bdDnsRegistrar, err := NewDNSRegistrarFromConf(dnsConf, true, connectionDelay, retriesPerRegistrar, dnsConf.GetPubkey())
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS registrar: %w", err)
	}

	registrars = append(registrars, bdDnsRegistrar)

	registrars = append(registrars, APIRegistrar{
		Endpoint:        apiEndpoint,
		ConnectionDelay: connectionDelay,
		MaxRetries:      retriesPerRegistrar,
	})

	dnsRegistrar, err := NewDNSRegistrarFromConf(dnsConf, false, connectionDelay, retriesPerRegistrar, dnsConf.GetPubkey())
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS registrar: %w", err)
	}

	registrars = append(registrars, dnsRegistrar)

	return &AutoRegistrar{
		registrars: registrars,
	}, nil
}

// Register calls the underlying registrars to register
func (r AutoRegistrar) Register(cjSession *ConjureSession, ctx context.Context) (*ConjureReg, error) {
	for _, registrar := range r.registrars {
		conjReg, err := registrar.Register(cjSession, ctx)
		if err != nil {
			Logger().Debugf("Auto registration failed: %v", err)
			continue
		}
		return conjReg, nil
	}

	return nil, errors.New("auto registration failed: no working registrar")
}
