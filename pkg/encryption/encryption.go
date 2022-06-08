package encryption

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/flynn/noise"
	"github.com/mingyech/conjure-dns-registrar/pkg/msgformat"
	"github.com/mingyech/conjure-dns-registrar/pkg/remotemap"
	"golang.org/x/crypto/curve25519"
)

const (
	KeyLen                    = 32
	handshakeMsgLen           = KeyLen + 16
	maxMsgLen           uint8 = 140
	recvTimeoutDuration       = 1 * time.Second
)

// cipherSuite represents 25519_ChaChaPoly_BLAKE2s.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

var recvChanMap remotemap.RemoteMap = *remotemap.NewRemoteMap(2 * time.Minute)

// Provides an interface to send and recieve messages over encryption through Write() and Read()
type EncryptedPacketConn struct {
	remoteAddr net.Addr
	sendCipher *noise.CipherState
	recvCipher *noise.CipherState
	recvChan   chan []byte
	net.PacketConn
}

// Listen for incomming messages from pconn, pushing to corresponding recvChan and new address to returned channel
func ListenMessages(pconn net.PacketConn) chan net.Addr {
	newAddrChan := make(chan net.Addr)
	go func() {
		for {
			var msg [maxMsgLen]byte
			_, recvAddr, err := pconn.ReadFrom(msg[:])
			if err != nil {
				log.Printf("listen message err: %v\n", err)
			}
			recvChan, isNewAddr := recvChanMap.GetChan(recvAddr)
			if isNewAddr {
				log.Printf("pushing new addr [%s] to newAddrChan", recvAddr.String())
				newAddrChan <- recvAddr
				log.Printf("pushed new addr [%s] to newAddrChan", recvAddr.String())
			}
			log.Printf("recieved msg from: [%s], msg content: [%v] pushing to corresponding recvChan\n", recvAddr.String(), msg[:])
			recvChan <- msg[:]
			log.Printf("Pushed")

		}
	}()
	return newAddrChan
}

// NewConfig instantiates configuration settings that are common to clients and
// servers.
func NewConfig() noise.Config {
	return noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeN,
	}
}

// ReadKey reads a hex-encoded key from r. r must consist of a single line, with
// or without a '\n' line terminator. The line must consist of KeyLen
// hex-encoded bytes.
func ReadKey(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(io.LimitReader(r, 100))
	line, err := br.ReadString('\n')
	if err == io.EOF {
		err = nil
	}
	if err == nil {
		// Check that we're at EOF.
		_, err = br.ReadByte()
		if err == io.EOF {
			err = nil
		} else if err == nil {
			err = fmt.Errorf("file contains more than one line")
		}
	}
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\n")
	return DecodeKey(line)
}

// DecodeKey decodes a hex-encoded private or public key.
func DecodeKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err == nil && len(key) != KeyLen {
		err = fmt.Errorf("length is %d, expected %d", len(key), KeyLen)
	}
	return key, err
}

// GeneratePrivkey generates a private key. The corresponding public key can be
// derived using PubkeyFromPrivkey.
func GeneratePrivkey() ([]byte, error) {
	pair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	return pair.Private, err
}

// PubkeyFromPrivkey returns the public key that corresponds to privkey.
func PubkeyFromPrivkey(privkey []byte) []byte {
	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pubkey
}

// Write writes encrypted data from the wrapped io.Writer.
func (e *EncryptedPacketConn) Write(p []byte) (int, error) {
	msg, err := e.sendCipher.Encrypt(nil, nil, p)
	if err != nil {
		return 0, err
	}
	length := uint8(len(msg))
	msgToSend := append([]byte{length}, msg...)
	return e.sendMsg(msgToSend)
}

func (e *EncryptedPacketConn) sendMsg(msg []byte) (int, error) {
	return e.WriteTo(msg, e.remoteAddr)
}

// Get msg from remote addr
func (e *EncryptedPacketConn) recvMsg(msg []byte) (int, error) {
	recvdMsg := <-e.recvChan
	copy(msg, recvdMsg)
	log.Printf("recvMsg(): writing msg: [%v]", msg)
	log.Printf("got msg from channel")
	return int(maxMsgLen), nil

}

// Read and decrypt incomming message
func (e *EncryptedPacketConn) Read(p []byte) (int, error) {
	var encryptedResponse [maxMsgLen]byte
	_, err := e.recvMsg(encryptedResponse[:])
	if err != nil {
		return 0, err
	}
	return e.handleReadMsg(p, encryptedResponse[:])
}

// Read the first byte as length of message, then try to decrypt it accordingly
func (e *EncryptedPacketConn) handleReadMsg(decrypted []byte, encryptedResponse []byte) (int, error) {
	length := uint8(encryptedResponse[0])
	if 1+length > maxMsgLen {
		return 0, errors.New("invalid message length recieved")
	}
	msg, err := e.recvCipher.Decrypt(nil, nil, encryptedResponse[1:1+length])
	copy(decrypted, msg)
	if err != nil {
		return 0, err
	}
	return len(msg), nil
}

// Put noise protocol over a PacketConn. Handle the initial handshake with server
func NewClient(pconn net.PacketConn, remote net.Addr, pubkey []byte) (*EncryptedPacketConn, error) {

	recvChan, _ := recvChanMap.GetChan(remote)

	e := &EncryptedPacketConn{
		PacketConn: pconn,
		remoteAddr: remote,
		recvChan:   recvChan,
	}
	config := NewConfig()
	serverPubkey := pubkey
	config.Initiator = true
	config.PeerStatic = serverPubkey
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	log.Println("start noise handshake")

	log.Println("-> e, es")
	// -> e, es

	toSend := ""
	for i := 0; i < 9; i++ {
		toSend += "x"
	}

	msgToSend, recvCipher, sendCipher, err := handshakeState.WriteMessage(nil, []byte(toSend))

	if err != nil {
		return nil, err
	}

	msgToSend, err = msgformat.AddFormat([]byte(msgToSend))

	if err != nil {
		return nil, err
	}

	_, err = e.sendMsg(msgToSend)

	if err != nil {
		return nil, err
	}

	toSend = ""
	for i := 0; i < 92; i++ {
		toSend += "x"
	}

	out, _ := sendCipher.Encrypt(nil, nil, []byte(toSend))

	log.Println("second: ", len(out))

	// // <- e, es
	// log.Println("<- e, es")
	// var recvMsg [handshakeMsgLen]byte

	// _, err = e.recvMsg(recvMsg[:])

	// if err != nil {
	// 	return nil, err
	// }

	// payload, sendCipher, recvCipher, err := handshakeState.ReadMessage(nil, recvMsg[:])

	// if err != nil {
	// 	return nil, err
	// }
	// if len(payload) != 0 {
	// 	return nil, errors.New("unexpected server payload")
	// }

	log.Println("noise handshake complete")

	e.sendCipher = sendCipher
	e.recvCipher = recvCipher
	return e, nil
}

// Put noise protocol over a PacketConn. Handle the initial handshake with client
func NewServer(pconn net.PacketConn, recvAddr net.Addr, privkey []byte) (*EncryptedPacketConn, error) {

	recvChan, _ := recvChanMap.GetChan(recvAddr)

	e := &EncryptedPacketConn{
		PacketConn: pconn,
		remoteAddr: recvAddr,
		recvChan:   recvChan,
	}
	config := NewConfig()
	config.Initiator = false
	config.StaticKeypair = noise.DHKey{
		Private: privkey,
		Public:  PubkeyFromPrivkey(privkey),
	}
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	log.Println("start noise handshake")

	log.Println("-> e, es")
	// -> e, es

	var recvMsg [140]byte

	_, err = e.recvMsg(recvMsg[:])
	log.Printf("Recieved msg from recvChan: [%v]", recvMsg)
	if err != nil {
		return nil, err
	}

	payload, sendCipher, recvCipher, err := handshakeState.ReadMessage(nil, recvMsg[:])

	if err != nil {
		return nil, err
	}

	// if len(payload) != 0 {
	// 	return nil, errors.New("unexpected server payload")
	// }
	log.Println(string(payload))

	// // <- e, es
	// log.Println("<- e, es")
	// msgToSend, recvCipher, sendCipher, err := handshakeState.WriteMessage(nil, nil)

	// if err != nil {
	// 	return nil, err
	// }

	// _, err = e.sendMsg(msgToSend)

	// if err != nil {
	// 	return nil, err
	// }

	log.Println("noise handshake complete")

	e.sendCipher = sendCipher
	e.recvCipher = recvCipher
	return e, nil
}
