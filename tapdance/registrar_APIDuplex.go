package tapdance

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// APIDuplexRegistrar Registration strategy using a centralized REST API to
// create registrations. Only the Endpoint need be specified;
// the remaining fields are valid with their zero values and
// provide the opportunity for additional control over the process.
type APIDuplexRegistrar struct {
	// Endpoint to use in registration request
	Endpoint string

	// HTTP client to use in request
	Client *http.Client

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
	SecondaryRegistrar Registrar
}

func (r APIDuplexRegistrar) Register(cjSession *ConjureSession, ctx context.Context) (*ConjureReg, error) {
	Logger().Debugf("%v registering via APIDuplexRegistrar", cjSession.IDString())
	// TODO: this section is duplicated from DecoyRegistrar; consider consolidating

	// [reference] Prepare registration
	reg := &ConjureReg{
		sessionIDStr:   cjSession.IDString(),
		keys:           cjSession.Keys,
		stats:          &pb.SessionStats{},
		v6Support:      cjSession.V6Support.include,
		covertAddress:  cjSession.CovertAddress,
		transport:      cjSession.Transport,
		TcpDialer:      cjSession.TcpDialer,
		useProxyHeader: cjSession.UseProxyHeader,
	}

	c2s := reg.generateClientToStation()

	protoPayload := pb.C2SWrapper{
		SharedSecret:        cjSession.Keys.SharedSecret,
		RegistrationPayload: c2s,
	}

	payload, err := proto.Marshal(&protoPayload)
	if err != nil {
		Logger().Warnf("%v failed to marshal ClientToStation payload: %v", cjSession.IDString(), err)
		return nil, err
	}

	if r.Client == nil {
		// Transports should ideally be re-used for TCP connection pooling,
		// but each registration is most likely making precisely one request,
		// or if it's making more than one, is most likely due to an underlying
		// connection issue rather than an application-level error anyways.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = reg.TcpDialer
		r.Client = &http.Client{Transport: t}
	}

	tries := 0
	for tries < r.MaxRetries+1 {
		tries++
		resp, err := r.executeHTTPRequest(cjSession, payload)
		if err != nil {
			Logger().Warnf("%v failed API registration, attempt %d/%d", cjSession.IDString(), tries, r.MaxRetries+1)
		}
		Logger().Debugf("%v API registration succeeded", cjSession.IDString())
		if r.ConnectionDelay != 0 {
			Logger().Debugf("%v sleeping for %v", cjSession.IDString(), r.ConnectionDelay)
			time.Sleep(r.ConnectionDelay)
		}
		payload := pb.ClientToStation{}
		err = proto.Unmarshal(resp, &payload)
		if err != nil {
			Logger().Warnf("failed to decode response body: %v", err)
			return nil, fmt.Errorf("failed to parse response body despite response code: %v", err)
		}
		return reg, nil
	}

	// If we make it here, we failed API registration
	Logger().Warnf("%v giving up on API registration", cjSession.IDString())

	if r.SecondaryRegistrar != nil {
		Logger().Debugf("%v trying secondary registration method", cjSession.IDString())
		return r.SecondaryRegistrar.Register(cjSession, ctx)
	}

	return nil, err
}

func (r APIDuplexRegistrar) executeHTTPRequest(cjSession *ConjureSession, payload []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		Logger().Warnf("%v failed to create HTTP request to registration endpoint %s: %v", cjSession.IDString(), r.Endpoint, err)
		return nil, err
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		Logger().Warnf("%v failed to do HTTP request to registration endpoint %s: %v", cjSession.IDString(), r.Endpoint, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		Logger().Warnf("%v got non-success response code %d from registration endpoint %v", cjSession.IDString(), resp.StatusCode, r.Endpoint)
		return nil, fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.Endpoint)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Logger().Warnf("%v encountered error while reading response from registration endpoint %s, %v", cjSession.IDString(), r.Endpoint, err)
		return nil, err
	}
	return body, nil
}
