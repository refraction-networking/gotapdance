package tapdance

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestAPIDuplexRegistrar(t *testing.T) {
	AssetsSetDir("./assets")
	session := makeConjureSession("1.2.3.4:1234", pb.TransportType_Obfs4)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("incorrect request method: expected POST, got %v", r.Method)
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		payload := pb.C2SWrapper{}
		err = proto.Unmarshal(body, &payload)
		if err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if payload.RegistrationPayload.GetCovertAddress() != "1.2.3.4:1234" {
			t.Fatalf("incorrect covert address: expected 1.2.3.4:1234, got %s", payload.RegistrationPayload.GetCovertAddress())
		}

		if !bytes.Equal(payload.GetSharedSecret(), session.Keys.SharedSecret) {
			t.Fatalf("incorrect shared secret: expected %v, got %v", session.Keys.SharedSecret, payload.GetSharedSecret())
		}

		resp, err := proto.Marshal(&payload)
		if err != nil {
			t.Fatalf("failed to marshal ClientToStation payload: %v", err)
		}

		w.Write(resp)
	}))

	registrar := APIDuplexRegistrar{
		Endpoint: server.URL,
		Client:   server.Client(),
	}

	registrar.Register(session, context.TODO())

	server.Close()
}
