package requester

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/flynn/noise"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/dns"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/encryption"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/msgformat"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/queuepacketconn"
	utls "github.com/refraction-networking/utls"
)

type Requester struct {
	// underlying transport used for the dns request
	transport net.PacketConn
	// remote address
	remoteAddr net.Addr
	// server public key
	pubkey []byte
}

// New Requester using DoT as transport
func NewDoTRequester(dotaddr string, domain string, pubkey []byte, utlsDistribution string, tcpDialer func(ctx context.Context, network, addr string) (net.Conn, error)) (*Requester, error) {
	basename, err := dns.ParseName(domain)
	if err != nil {
		return nil, err
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		return nil, err
	}

	if tcpDialer == nil {
		dialer := net.Dialer{}
		tcpDialer = dialer.DialContext
	}

	remoteAddr := queuepacketconn.DummyAddr{}
	var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if utlsClientHelloID == nil {
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := tcpDialer(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, &tls.Config{}), nil
		}
	} else {
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID, tcpDialer)
		}
	}
	dotconn, err := NewTLSPacketConn(dotaddr, dialTLSContext)
	if err != nil {
		return nil, err
	}

	pconn := NewDNSPacketConn(dotconn, remoteAddr, basename)

	return &Requester{
		transport:  pconn,
		remoteAddr: remoteAddr,
		pubkey:     pubkey,
	}, nil
}

// New Requester using DoH as transport
func NewDoHRequester(dohurl string, domain string, pubkey []byte, utlsDistribution string, tcpDialer func(ctx context.Context, network, addr string) (net.Conn, error)) (*Requester, error) {
	basename, err := dns.ParseName(domain)
	if err != nil {
		return nil, err
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		return nil, err
	}

	remoteAddr := queuepacketconn.DummyAddr{}
	var rt http.RoundTripper
	if utlsClientHelloID == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// Disable DefaultTransport's default Proxy =
		// ProxyFromEnvironment setting, for conformity
		// with utlsRoundTripper and with DoT mode,
		// which do not take a proxy from the
		// environment.
		transport.DialContext = tcpDialer
		transport.Proxy = nil
		rt = transport
	} else {
		rt = NewUTLSRoundTripper(nil, utlsClientHelloID, tcpDialer)
	}

	dohconn, err := NewHTTPPacketConn(rt, dohurl, 32)
	if err != nil {
		return nil, err
	}

	pconn := NewDNSPacketConn(dohconn, remoteAddr, basename)

	return &Requester{
		transport:  pconn,
		remoteAddr: remoteAddr,
		pubkey:     pubkey,
	}, nil
}

// New Requester using plain UDP as transport
func NewUDPRequester(remoteAddr net.Addr, domain string, pubkey []byte, udpDialer func(ctx context.Context, network, addr string) (net.Conn, error)) (*Requester, error) {
	basename, err := dns.ParseName(domain)
	if err != nil {
		return nil, fmt.Errorf("error parsing domain: %v", err)
	}

	conn, err := udpDialer(context.Background(), "udp", "")
	if err != nil {
		return nil, fmt.Errorf("error dialing udp connection: %v", err)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("error dialing udp connection: dialed conn from dialer cannot be asserted to net.UDPConn")
	}

	pconn := NewDNSPacketConn(udpConn, remoteAddr, basename)
	return &Requester{
		transport:  pconn,
		remoteAddr: remoteAddr,
		pubkey:     pubkey,
	}, nil
}

// Send the payload together with noise handshake, returns noise recvCipher for decrypting response
func (r *Requester) sendHandshake(payload []byte) (*noise.CipherState, *noise.CipherState, error) {
	config := encryption.NewConfig()
	config.Initiator = true
	config.PeerStatic = r.pubkey
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, err
	}
	msgToSend, recvCipher, sendCipher, err := handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, err
	}
	msgToSend, err = msgformat.AddRequestFormat([]byte(msgToSend))
	if err != nil {
		return nil, nil, err
	}
	_, err = r.transport.WriteTo(msgToSend, r.remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	return recvCipher, sendCipher, nil
}

func (r *Requester) RequestAndRecv(sendBytes []byte) ([]byte, error) {
	recvCipher, _, err := r.sendHandshake(sendBytes)
	if err != nil {
		return nil, err
	}

	var recvBuf [4096]byte
	for {
		_, recvAddr, err := r.transport.ReadFrom(recvBuf[:])
		if err != nil {
			return nil, err
		}
		if recvAddr.String() == r.remoteAddr.String() {
			break
		}
	}

	encryptedBuf, err := msgformat.RemoveResponseFormat(recvBuf[:])
	if err != nil {
		return nil, err
	}

	recvBytes, err := recvCipher.Decrypt(nil, nil, encryptedBuf)
	if err != nil {
		return nil, err
	}

	return recvBytes, nil
}

func (r *Requester) Close() error {
	return r.transport.Close()
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}
