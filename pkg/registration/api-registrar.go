package registration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
)

// Registration strategy using a centralized REST API to
// create registrations. Only the Endpoint need be specified;
// the remaining fields are valid with their zero values and
// provide the opportunity for additional control over the process.
type APIRegistrar struct {
	// Endpoint to use in registration request
	Endpoint string

	// HTTP client to use in request
	Client *http.Client

	Bidirectional bool

	// Length of time to delay after confirming successful
	// registration before attempting a connection,
	// allowing for propagation throughout the stations.
	ConnectionDelay time.Duration

	// Maximum number of retries before giving up
	MaxRetries int

	// A secondary registration method to use on failure.
	// Because the API registration can give us definite
	// indication of a failure to register, this can be
	// used as a "backup" in the case of the API being
	// down or being blocked.
	//
	// If this field is nil, no secondary registration will
	// be attempted. If it is non-nil, after failing to register
	// (retrying MaxRetries times) we will fall back to
	// the Register method on this field.
	SecondaryRegistrar tapdance.Registrar

	Logger logrus.FieldLogger
}

// registerUnidirectional sends unidirectional registration data to the registration server
func (r *APIRegistrar) registerUnidirectional(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	logger := r.Logger.WithFields(logrus.Fields{"type": "unidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.UnidirectionalRegData(pb.RegistrationSource_API.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, ErrRegFailed
	}

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, ErrRegFailed
	}

	r.setHTTPClient(reg)

	for tries := 0; tries < r.MaxRetries+1; tries++ {
		logger := logger.WithField("attempt", strconv.Itoa(tries+1)+"/"+strconv.Itoa(r.MaxRetries+1))
		err = r.executeHTTPRequest(ctx, payload, logger)
		if err != nil {
			logger.Warnf("error in registration attempt: %v", err)
			continue
		}
		logger.Debugf("registration succeeded")
		return reg, nil
	}

	// If we make it here, we failed API registration
	logger.WithField("attempts", r.MaxRetries+1).Warnf("all registration attempt(s) failed")

	if r.SecondaryRegistrar != nil {
		logger.Debugf("trying secondary registration method")
		return r.SecondaryRegistrar.Register(cjSession, ctx)
	}

	return nil, ErrRegFailed
}

// registerBidirectional sends bidirectional registration data to the registration server and reads the response
func (r *APIRegistrar) registerBidirectional(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	logger := r.Logger.WithFields(logrus.Fields{"type": "bidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.BidirectionalRegData(pb.RegistrationSource_BidirectionalAPI.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, ErrRegFailed
	}

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, ErrRegFailed
	}

	r.setHTTPClient(reg)

	for tries := 0; tries < r.MaxRetries+1; tries++ {
		logger := logger.WithField("attempt", strconv.Itoa(tries+1)+"/"+strconv.Itoa(r.MaxRetries+1))

		regResp, err := r.executeHTTPRequestBidirectional(ctx, payload, logger)
		if err != nil {
			logger.Warnf("error in registration attempt: %v", err)
			continue
		}

		reg.UnpackRegResp(regResp)
		return reg, nil
	}

	// If we make it here, we failed API registration
	logger.WithField("attempts", r.MaxRetries+1).Warnf("all registration attempt(s) failed")

	if r.SecondaryRegistrar != nil {
		logger.Debugf("trying secondary registration method")
		return r.SecondaryRegistrar.Register(cjSession, ctx)
	}

	return nil, ErrRegFailed
}

func (r *APIRegistrar) setHTTPClient(reg *tapdance.ConjureReg) {
	if r.Client == nil {
		// Transports should ideally be re-used for TCP connection pooling,
		// but each registration is most likely making precisely one request,
		// or if it's making more than one, is most likely due to an underlying
		// connection issue rather than an application-level error anyways.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = reg.TcpDialer
		r.Client = &http.Client{Transport: t}
	}
}

func (r APIRegistrar) Register(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	defer sleepWithContext(ctx, r.ConnectionDelay)

	if r.Bidirectional {
		return r.registerBidirectional(cjSession, ctx)
	}

	return r.registerUnidirectional(cjSession, ctx)

}

func (r APIRegistrar) executeHTTPRequest(ctx context.Context, payload []byte, logger logrus.FieldLogger) error {
	req, err := http.NewRequestWithContext(ctx, "POST", r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		logger.Warnf("failed to create HTTP request to registration endpoint %s: %v", r.Endpoint, err)
		return err
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		logger.Warnf("failed to do HTTP request to registration endpoint %s: %v", r.Endpoint, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warnf("%v got non-success response code %d from registration endpoint %v", resp.StatusCode, r.Endpoint)
		return fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.Endpoint)
	}

	return nil
}

func (r APIRegistrar) executeHTTPRequestBidirectional(ctx context.Context, payload []byte, logger logrus.FieldLogger) (*pb.RegistrationResponse, error) {
	// Create an instance of the ConjureReg struct to return; this will hold the updated phantom4 and phantom6 addresses received from registrar response
	regResp := &pb.RegistrationResponse{}
	// Make new HTTP request with given context, registrar, and paylaod
	req, err := http.NewRequestWithContext(ctx, "POST", r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		logger.Warnf("%v failed to create HTTP request to registration endpoint %s: %v", r.Endpoint, err)
		return regResp, err
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		logger.Warnf("%v failed to do HTTP request to registration endpoint %s: %v", r.Endpoint, err)
		return regResp, err
	}
	defer resp.Body.Close()

	// Check that the HTTP request returned a success code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warnf("%v got non-success response code %d from registration endpoint %v", resp.StatusCode, r.Endpoint)
		return regResp, fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.Endpoint)
	}

	// Read the HTTP response body into []bytes
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("error in serializing Registrtion Response protobuf in bytes: %v", err)
		return regResp, err
	}

	// Unmarshal response body into Registration Response protobuf
	if err = proto.Unmarshal(bodyBytes, regResp); err != nil {
		logger.Warnf("error in storing Registrtion Response protobuf: %v", err)
		return regResp, err
	}

	return regResp, nil
}
