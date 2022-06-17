package requester

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/flynn/noise"
	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
	"github.com/mingyech/conjure-dns-registrar/pkg/encryption"
	"github.com/mingyech/conjure-dns-registrar/pkg/msgformat"
	"github.com/mingyech/conjure-dns-registrar/pkg/queuepacketconn"
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
func NewDoTRequester(dotaddr string, domain string, pubkey []byte, utlsDistribution string) (*Requester, error) {
	basename, err := dns.ParseName(domain)
	if err != nil {
		return nil, err
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		return nil, err
	}

	remoteAddr := queuepacketconn.DummyAddr{}
	var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if utlsClientHelloID == nil {
		dialTLSContext = (&tls.Dialer{}).DialContext
	} else {
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
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
func NewDoHRequester(dohurl string, domain string, pubkey []byte, utlsDistribution string) (*Requester, error) {
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
		transport.Proxy = nil
		rt = transport
	} else {
		rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
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
func NewUDPRequester(remoteAddr net.Addr, domain string, pubkey []byte) (*Requester, error) {
	basename, err := dns.ParseName(domain)
	if err != nil {
		return nil, err
	}

	udpconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	pconn := NewDNSPacketConn(udpconn, remoteAddr, basename)
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

// readKeyFromFile reads a key from a named file
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return encryption.ReadKey(f)
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

// Send the payload together with noise handshake, returns noise recvCipher for decrypting response
func sendHandshake(pconn net.PacketConn, remoteAddr net.Addr, pubkey []byte, payload []byte) (*noise.CipherState, *noise.CipherState, error) {

	config := encryption.NewConfig()
	config.Initiator = true
	config.PeerStatic = pubkey
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
	_, err = pconn.WriteTo(msgToSend, remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	return recvCipher, sendCipher, nil
}

func handle(pconn net.PacketConn, remoteAddr net.Addr, pubkey []byte, sendBytes []byte) ([]byte, error) {
	recvCipher, _, err := sendHandshake(pconn, remoteAddr, pubkey, sendBytes)
	if err != nil {
		return nil, err
	}

	var recvBuf [4096]byte
	for {
		_, recvAddr, err := pconn.ReadFrom(recvBuf[:])
		if err != nil {
			return nil, err
		}
		if recvAddr.String() == remoteAddr.String() {
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

func run(domain dns.Name, remoteAddr net.Addr, pconn net.PacketConn, msg string, pubkey []byte) error {
	defer pconn.Close()

	recvBytes, err := handle(pconn, remoteAddr, pubkey, []byte(msg))
	if err != nil {
		log.Printf("handle: %v\n", err)
	}
	log.Printf("Received: [%s]", string(recvBytes))
	return nil
}

func main() {
	var updaddr string
	var domain string
	var msg string
	var pubkeyFilename string
	var dohaddr string
	var dotaddr string
	var utlsDistribution string
	flag.StringVar(&updaddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&dohaddr, "doh", "", "address of DoH DNS resolver")
	flag.StringVar(&dotaddr, "dot", "", "address of DoT DNS resolver")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
	flag.StringVar(&msg, "msg", "hi", "message to send")
	flag.StringVar(&pubkeyFilename, "pubkey", "", "server public key")
	flag.StringVar(&utlsDistribution, "utls",
		"3*Firefox_65,1*Firefox_63,1*iOS_12_1",
		"choose TLS fingerprint from weighted distribution")
	flag.Parse()
	if pubkeyFilename == "" {
		fmt.Println("Server public key must be provided")
		flag.Usage()
		os.Exit(2)
	}

	if domain == "" {
		fmt.Println("domain must be specified")
		flag.Usage()
		os.Exit(2)
	}

	basename, err := dns.ParseName(domain)

	if err != nil {
		log.Fatal(err)
	}

	var pconn net.PacketConn
	var remoteAddr net.Addr
	if updaddr != "" {
		remoteAddr, err = net.ResolveUDPAddr("udp", updaddr)
		if err != nil {
			log.Fatal(err)
		}
		pconn, err = net.ListenUDP("udp", nil)

		if err != nil {
			log.Fatal(err)
		}

	}
	if dohaddr != "" || dotaddr != "" {
		if pconn != nil {
			fmt.Println("Only one of -udp, -doh, -dot may be provided")
			flag.Usage()
			os.Exit(2)
		}

		utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
		if err != nil {
			log.Fatal(err)
		}
		if utlsClientHelloID != nil {
			log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
		}

		if dohaddr != "" {
			remoteAddr = queuepacketconn.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			pconn, err = NewHTTPPacketConn(rt, dohaddr, 32)
			if err != nil {
				log.Fatal(err)
			}
		}
		if dotaddr != "" {
			if pconn != nil {
				fmt.Println("Only one of -udp, -doh, -dot may be provided")
				flag.Usage()
				os.Exit(2)
			}

			remoteAddr = queuepacketconn.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			pconn, err = NewTLSPacketConn(dotaddr, dialTLSContext)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	if pconn == nil {
		fmt.Println("One of -udp, -doh, -dot must be provided")
		flag.Usage()
		os.Exit(2)
	}

	pubkey, err := readKeyFromFile(pubkeyFilename)

	if err != nil {
		log.Fatal(err)
	}

	pconn = NewDNSPacketConn(pconn, remoteAddr, basename)
	err = run(basename, remoteAddr, pconn, msg, pubkey)
	if err != nil {
		log.Fatal(err)
	}
}
