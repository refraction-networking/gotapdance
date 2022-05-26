package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/flynn/noise"
	"github.com/mingyech/conjure-dns-registrar/pkg/dns"
	"github.com/mingyech/conjure-dns-registrar/pkg/noisehelpers"
)

const (
	bufSize = 4096
	KeyLen  = 32
)

// cipherSuite represents 25519_ChaChaPoly_BLAKE2s.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// newConfig instantiates configuration settings that are common to clients and
// servers.
func newConfig() noise.Config {
	return noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeNK,
		Prologue:    []byte("dnstt 2020-04-13"),
	}
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noisehelpers.ReadKey(f)
}

func handle(pconn net.PacketConn, remoteAddr *net.UDPAddr, msg string, pubkey []byte) error {

	config := newConfig()
	serverPubkey := pubkey
	config.Initiator = true
	config.PeerStatic = serverPubkey
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return err
	}

	log.Println("start noise handshake")

	log.Println("-> e, es")
	// -> e, es
	msgToSend, _, _, err := handshakeState.WriteMessage(nil, nil)

	if err != nil {
		return err
	}

	_, err = pconn.WriteTo(msgToSend, remoteAddr)
	if err != nil {
		return err
	}

	log.Println("e, es sent")

	// <- e, es
	log.Println("<- e, es")
	var recvMsg [bufSize]byte
	_, recvAddr, err := pconn.ReadFrom(recvMsg[:])

	if err != nil {
		return nil
	}
	payload, sendCipher, recvCipher, err := handshakeState.ReadMessage(nil, recvMsg[:])

	log.Println("e, es recieved")

	if err != nil {
		return nil
	}
	if len(payload) != 0 {
		return errors.New("unexpected server payload")
	}

	log.Println("noise handshake complete")

	encryptedMsg, err := sendCipher.Encrypt(nil, nil, []byte(msg))

	if err != nil {
		return errors.New("encrypt failed")
	}

	_, err = pconn.WriteTo(encryptedMsg, remoteAddr)

	if err != nil {
		log.Fatalf("stream :%s write: [%s], err: %v\n", remoteAddr.String(), msg, err)
	}

	log.Printf("Sent: [%s]\n", msg)

	var encryptedResponse [bufSize]byte

	_, recvAddr, err = pconn.ReadFrom(encryptedResponse[:])

	if err != nil {
		return errors.New("recv failed")
	}
	responseBuf, err := recvCipher.Decrypt(nil, nil, encryptedResponse[:])
	if err != nil {
		return errors.New("decrypt failed")
	}

	response := string(responseBuf[:])
	if err != nil {
		log.Fatalf("stream: %s: server: %s: read: [%s], err: %v\n", remoteAddr.String(), recvAddr.String(), response, err)
	}
	fmt.Printf("Response: [%s]\n", response)

	return nil
}

func run(domain dns.Name, remoteAddr *net.UDPAddr, pconn net.PacketConn, msg string, pubkey []byte) error {
	defer pconn.Close()

	// TODO: add encryption
	err := handle(pconn, remoteAddr, msg, pubkey)
	if err != nil {
		log.Printf("handle: %v\n", err)
	}
	return nil
}

func main() {
	var addr string
	var domain string
	var msg string
	var pubkeyFilename string
	flag.StringVar(&addr, "addr", "", "address of DNS resolver")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
	flag.StringVar(&msg, "msg", "hi", "message to send")
	flag.StringVar(&pubkeyFilename, "pubkey", "", "server public key")
	flag.Parse()
	if addr == "" {
		fmt.Println("DNS resolver address must be specified")
		flag.Usage()
		os.Exit(2)
	}

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

	var pconn net.PacketConn
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	basename, err := dns.ParseName(domain)

	if err != nil {
		log.Fatal(err)
	}

	pconn, err = net.ListenUDP("udp", nil)

	if err != nil {
		log.Fatal(err)
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
