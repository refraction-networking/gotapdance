package tapdance

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AutoRegistrar stores multiple registrars and calls each until a success
type AutoRegistrar struct {
	registrars []Registrar
}

// NewAutoRegistrar creates an AutoRegistrar from configuration stored in assets
func NewAutoRegistrar() (*AutoRegistrar, error) {
	registrars := []Registrar{}
	registrars = append(registrars, DecoyRegistrar{})

	apiEndpoint := "https://registration.refraction.network/api/register" // will be configured via ClientConf in the future
	registrars = append(registrars, APIRegistrar{
		Endpoint:        apiEndpoint,
		ConnectionDelay: 750 * time.Millisecond,
		MaxRetries:      3,
	})

	dnsConf := Assets().GetDNSRegConf()
	dnsRegistrar, err := NewDNSRegistrarFromConf(dnsConf, false, 750*time.Millisecond, 3, Assets().GetConjurePubkey()[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS registrar: %w", err)
	}

	registrars = append(registrars, dnsRegistrar)

	return &AutoRegistrar{
		registrars: registrars,
	}, nil
}

// NewBdAutoRegistrar creates an bidirectional AutoRegistrar from configuration stored in assets
func NewBdAutoRegistrar() (*AutoRegistrar, error) {
	registrars := []Registrar{}

	// URL for API registrar, will be configured via ClientConf in the future
	apiEndpoint := "https://registration.refraction.network/api/register-bidirectional" // will be configured via ClientConf in the future
	registrars = append(registrars, APIRegistrarBidirectional{
		Endpoint:        apiEndpoint,
		ConnectionDelay: 750 * time.Millisecond,
		MaxRetries:      3,
	})

	dnsConf := Assets().GetDNSRegConf()
	dnsRegistrar, err := NewDNSRegistrarFromConf(dnsConf, true, 750*time.Millisecond, 3, Assets().GetConjurePubkey()[:])
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
