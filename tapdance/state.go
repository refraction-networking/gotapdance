package tapdance

import (
	"github.com/zmap/zgrab/ztools/ztls"
	"encoding/binary"
	"crypto/cipher"
	"net"
	"bytes"

	"strconv"

	"time"

	"errors"
	"crypto/rand"
)

const (
	MSG_DATA = iota // iota auto increments
	MSG_INIT
	MSG_RECONNECT
	MSG_CLOSE
)


// Connection-oriented state
type TDConnState struct {
	clientRandom   []byte
	serverRandom   []byte

	decoyHost      string
	decoyPort    int

	realHost     string // todo Do I need it?
	realPort     int

			    // tunnel index and start time
	id           uint
	startMs      uint64
	name         string

			    // reference to global proxy
	proxy        *TapdanceProxy

	servConn     *ztls.Conn
	userConn     net.Conn

			    /* random per-connection (secret) id;
			     this way, the underlying SSL connection can disconnect
			     while the client's local conn and station's proxy conn
			     can stay connected */
	remoteConnId [16]byte

			    /* Set to 1 as soon as we learn (from proxy channel) that
			     we need to. This keeps a ISREMOTE EV_ERROR or EOF from cleaning
			     up the state */
	retryConn    int

			    /* Maximum amount of data we can send to the station
			     before we should tear-down the connection for a new one
			     with the same remote_conn_id */
	maxSend      uint64
	sentTotal    uint64
	reconnecting bool

	winSize      uint16
};

// constructor
func NewTapdanceState(proxy *TapdanceProxy, decoyHost string, decoyPort int, id uint) *TDConnState {
	state := new(TDConnState)

	state.decoyHost = decoyHost
	state.decoyPort = decoyPort

	state.proxy = proxy
	state.id = id

	state.startMs = uint64(timeMs())

	state.name = "tunnel" + strconv.FormatUint(uint64(state.id), 10)

	rand.Read(state.remoteConnId[:])

	state.maxSend = 16*1024 - 1
	state.reconnecting = false

	Logger.Debugf("Created new TDState ", state)
	return state
}

func (TDstate *TDConnState) Connect() (err error) {
	err = TDstate.establishTLStoDecoy()
	if err != nil {
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10) +
			"] establishTLStoDecoy() failed with " + err.Error())
		return
	} else {
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10) +
			"] Connected to decoy " + TDstate.decoyHost)
	}
	var tdRequest string
	tdRequest, err = TDstate.prepareTDRequest()
	if err != nil {
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10) +
			"] Preparation of initial TD request failed with " + err.Error())
		return
	}
	err = TDstate.WriteToServer(tdRequest)
	if err != nil {
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10) +
			"] Could not send initial TD request, error: " + err.Error())
		return
	}
	msgType, _, err := TDstate.ReadFromServer()
	if err != nil {
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10) +
			"] Could not read from server after sending initial TD request, error: " +
			err.Error())
		return
	}
	if msgType != MSG_INIT {
		err = errors.New("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10) +
			"] Initial message was not MSG_INIT(1), but " + string(msgType))
		Logger.Errorf(err.Error())
	}
	return
}

func (TDstate *TDConnState) establishTLStoDecoy() (err error) {
	//TODO: force stream cipher
	addr := TDstate.decoyHost + ":" + strconv.Itoa(TDstate.decoyPort)
	config := &ztls.Config{RootCAs: TDstate.proxy.roots, // MinVersion:ztls.VersionTLS10,
		InsecureSkipVerify: true} // TODO: remove InsecureSkipVerify
	TDstate.servConn, err = ztls.Dial("tcp", addr, config)
	if err != nil {
		return
	}
	TDstate.clientRandom = TDstate.servConn.GetHandshakeLog().ClientHello.Random
	TDstate.serverRandom = TDstate.servConn.GetHandshakeLog().ServerHello.Random
	//Logger.Debugf("After establishing the TLS conn to Decoy: Connection is ", TDstate.servConn)
	return
}

func (TDstate *TDConnState) getKeystream(length int) []byte {
	// get current state of cipher and encrypt zeros to get keystream
	zeros := make([]byte, length)
	servConnCipher := TDstate.servConn.OutCipher().(cipher.AEAD)
	keystreamWtag := servConnCipher.Seal(nil, TDstate.servConn.OutSeq(), zeros, nil)
	return keystreamWtag[:length]
}

func reverseEncrypt(ciphertext []byte, keyStream []byte) (plaintext string) {
	// our plaintext can be antyhing where x & 0xc0 == 0x40
	// i.e. 64-127 in ascii (@, A-Z, [\]^_`, a-z, {|}~ DEL)
	// This means that we are allowed to choose the last 6 bits
	// of each byte in the ciphertext arbitrarily; the upper 2
	// bits will have to be 01, so that our plaintext ends up
	// in the desired range.
	var ka, kb, kc, kd byte    // key stream bytes
	var ca, cb, cc, cd byte    // ciphertext bytes
	var pa, pb, pc, pd byte    // plaintext bytes
	var sa, sb, sc byte        // secret bytes

	var tag_idx, keystream_idx int

	for tag_idx < len(ciphertext) {
		ka = keyStream[keystream_idx]
		kb = keyStream[keystream_idx + 1]
		kc = keyStream[keystream_idx + 2]
		kd = keyStream[keystream_idx + 3]
		keystream_idx += 4

		// read 3 bytes
		sa = ciphertext[tag_idx]
		sb = ciphertext[tag_idx + 1]
		sc = ciphertext[tag_idx + 2]
		tag_idx += 3

		// figure out what plaintext needs to be in base64 encode
		ca = (ka & 0xc0) | ((sa & 0xfc) >> 2)                        // 6 bits sa
		cb = (kb & 0xc0) | (((sa & 0x03) << 4) | ((sb & 0xf0) >> 4)) // 2 bits sa, 4 bits sb
		cc = (kc & 0xc0) | (((sb & 0x0f) << 2) | ((sc & 0xc0) >> 6)) // 4 bits sb, 2 bits sc
		cd = (kd & 0xc0) | (sc & 0x3f)                               // 6 bits sc

		// Xor with key_stream, and add on 0x40 so it's in range of allowed
		pa = (ca ^ ka) + 0x40
		pb = (cb ^ kb) + 0x40
		pc = (cc ^ kc) + 0x40
		pd = (cd ^ kd) + 0x40

		plaintext += string(pa)
		plaintext += string(pb)
		plaintext += string(pc)
		plaintext += string(pd)
	}
	return
}

func (TDstate *TDConnState) prepareTDRequest() (tdRequest string, err error) {
	// Generate initial TapDance request
	buf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES

	master_key := TDstate.servConn.GetHandshakeLog().KeyMaterial.MasterSecret.Value
	if _, err = buf.WriteString(initial_tag); err != nil {
		return
	}
	if err = binary.Write(buf, binary.BigEndian, uint8(len(master_key))); err != nil {
		return
	}
	buf.Write(master_key[:])
	buf.Write(TDstate.serverRandom[:])
	buf.Write(TDstate.clientRandom[:])
	buf.Write(TDstate.remoteConnId[:]) // connection id for persistence

	tag, err := obfuscateTag(buf.Bytes(), TDstate.proxy.stationPubkey) // What we encode into the ciphertext
	if err != nil {
		return
	}
	//print_hex(tag, "tag")

	tdRequest = "GET / HTTP/1.1\r\nHost: www.example.cn\r\nX-Ignore: "
	keystreamOffset := len(tdRequest)
	//Logger.Debugf("tag", tag)
	keystreamSize := (len(tag) / 3  + 1) * 4 + keystreamOffset // we can't use first 2 bits of every byte
	whole_keystream := TDstate.getKeystream(keystreamSize)
	keystreamAtTag := whole_keystream[keystreamOffset:]
	//Logger.Debugf("keystream", keystream)
	//print_hex(keystream_at_tag, "keystream_at_tag")

	// req := "GET / HTTP/1.1\r\nHost:" + TDstate.decoy_host + "\r\nX-Ignore: "
	tdRequest += reverseEncrypt(tag, keystreamAtTag)
	Logger.Debugf("Prepared initial request to Decoy")//, td_request)

	return
}

func (TDstate *TDConnState) WriteToServer(request string) (err error) {
	// Used once to establish initial connection
	TDstate.servConn.SetWriteDeadline(time.Now().Add(time.Second * 20)) // Timeout in 20 secs
	Logger.Debugf("Trying to write to Server: ", request)
	n, err := TDstate.servConn.Write([]byte(request))
	if err != nil {
		return
	}
	if n != len(request) {
		err = errors.New("Expected to write " + strconv.Itoa(len(request)) + " bytes on initial request." +
		                 "But wrote " + strconv.Itoa(n) + " bytes. Aborting.")
		return
	}
	TDstate.sentTotal += uint64(n)
	Logger.Debugf("Successfully wrote to server")
	return
}

func (TDstate *TDConnState) WriteToClient(request []byte) (err error) {
	// Used to shove data back to Client in Redirect phase
	//servConn

	// TODO: https://blog.filippo.io/the-complete-guide-to-go-net-http-timeouts/
	TDstate.userConn.SetWriteDeadline(time.Now().Add(time.Second * 2)) // Timeout in 2 secs
	Logger.Debugf("Trying to write to Client: ", string(request))
	n, err := TDstate.userConn.Write(request)
	if err != nil {
		return
	}
	if n != len(request) {
		Logger.Warningf("Expected to write " + strconv.Itoa(len(request)) + " bytes to client." +
		"But wrote " + strconv.Itoa(n) + " bytes. Moving on.")
		return
	} else {
		Logger.Debugf("Successfully wrote to Client")
	}
	return
}


func (TDstate *TDConnState) ReadFromServer() (msgType uint8, message []byte, err error) {
	// 1 byte of each message is MSG_TYPE
	// 2-3: length of message
	// if MSG_TYPE == INIT:
	//   4-5: magic_val
	//   6-7: window size
	// if MSG_TYPE == DATA:
	//    DATA
	// if MSG_TYPE == (CLOSE or RECONNECT):
	//    EOF
	// TODO: unhardcode timeouts
	TDstate.servConn.SetReadDeadline(time.Now().Add(time.Second * 20)) // Timeout in 20 secs
	var bufSize, readBytesTotal uint16
	var readBytes int
	// TODO: switch to bytes.Buffer?
	bufSize = 2 * 4096 // TODO: justify the size
	buf := make([]byte, bufSize) // TODO: move buf to struct?

	for readBytesTotal < 3 {
		readBytes, err = TDstate.servConn.Read(buf[readBytesTotal:])
		if TDstate.reconnecting {
			time.Sleep(100 * time.Millisecond)
		} else {
			if err != nil {
				return
			}
			readBytesTotal += uint16(readBytes)
		}
	}
	var msgLen, magicVal, expectedMagicVal, winSize uint16
	msgType = buf[0]
	msgLen = binary.BigEndian.Uint16(buf[1:3])

	var headerSize uint16
	if msgType == MSG_INIT {
		headerSize = 7
	} else {
		headerSize = 3
	}

	// extend buf, if needed
	/* TODO:
	if msg_len + header_size > buf_size {
		additional_space := make([]byte, msg_len + 4096)
		buf = append(buf, additional_space)
	}
	*/

	// get the rest of the msg
	for msgLen + headerSize < readBytesTotal {
		readBytes, err = TDstate.servConn.Read(buf[readBytesTotal:])
		if TDstate.reconnecting {
			time.Sleep(100 * time.Millisecond)
		} else {
			if err != nil {
				return
			}
			readBytesTotal += uint16(readBytes)
		}
	}

	if msgType == MSG_INIT {
		// TODO: move away?
		magicVal = binary.BigEndian.Uint16(buf[3:5])
		winSize = binary.BigEndian.Uint16(buf[5:7])
		expectedMagicVal = uint16(0x2a75)
		if magicVal != expectedMagicVal {
			err = errors.New("INIT message: magic value mismatch! Expected: " +
					strconv.FormatUint(uint64(expectedMagicVal), 10) +
					", but received: " + strconv.FormatUint(uint64(magicVal), 10))
			return
		}
		TDstate.winSize = winSize
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
			"] Successfully connected to Tapdance Station!")
	} else if msgType == MSG_DATA {
		message = buf[headerSize:readBytesTotal]
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
			"] Successfully read DATA msg from server: " + string(message))
	}

	return
}

func (TDstate *TDConnState) Redirect() error {
	errChan := make(chan error)
	defer TDstate.userConn.Close()
	defer TDstate.servConn.Close()

	forwardFromServerToClient := func ()() {
		for !TDstate.proxy.stop {
			msgType, msg, err := TDstate.ReadFromServer()
			if err != nil {
				errChan <- err
				return
			}
			switch msgType {
			case MSG_INIT:
				err = errors.New("Received MSG_INIT in existing conn")
				errChan <- err
				return
			case MSG_CLOSE:
				err = errors.New("EOF")
				errChan <- err
				return
			case MSG_RECONNECT:
				// TODO
				err = errors.New("MSG_RECONNECT is not supported")
				errChan <- err
				return
			case MSG_DATA:
				err = TDstate.WriteToClient(msg)
				if err != nil {
					errChan <- err
					return
				}
			}
		}
	}

	forwardFromClientToServer := func ()() {
		//n, err := io.Copy(TDstate.servConn, TDstate.userConn)
		//Logger.Infof("Closed forwardFromClientToServer(): copied %d bytes", n)
		var err error

		send_buffer := func(buffer []byte)(err error) {
			_, err = TDstate.servConn.Write(buffer[:])
			if err != nil {
				Logger.Debugf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
					"] Failed to write to Server: " + string(buffer[:]))
			} else {
				Logger.Debugf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
					"] Wrote to Server: " + string(buffer[:]))
			}
			return
		}

		for !TDstate.proxy.stop {
			// TODO: use io.Copy
			bufSize := 16 * 1024 + 20 + 20 + 12 // From linux-2.6-stable/drivers/net/loopback.c
			// TODO: handle size in a more meaningful way
			buf := make([]byte, bufSize)

			totalToSendInt, err := TDstate.userConn.Read(buf[:])
			if err != nil {
				break
			}
			totalToSend := uint64(totalToSendInt)
			sentTotal := uint64(0)
			Logger.Debugf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
				"] Already sent: " + strconv.FormatUint(TDstate.sentTotal, 10) +
				". Requested to send: " + strconv.FormatUint(totalToSend, 10))
			for sentTotal != totalToSend {
				couldSend := TDstate.maxSend - TDstate.sentTotal
				if couldSend > totalToSend - sentTotal {
					err = send_buffer(buf[sentTotal:totalToSend])
					TDstate.sentTotal += (totalToSend - sentTotal)
					sentTotal = totalToSend
				} else {
					err = send_buffer(buf[sentTotal:sentTotal + couldSend])
					sentTotal += couldSend
					if err != nil {
						break
					}
					Logger.Infof("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
						"] Sent maximum " + strconv.FormatUint(TDstate.maxSend + couldSend, 10) +
						" bytes. Reconnecting to Tapdance.")
					TDstate.reconnecting = true
					TDstate.servConn.Close()
					err = TDstate.Connect()
					TDstate.sentTotal = 0
					TDstate.reconnecting = false
				}
				if err != nil {
					break
				}
			}
		}

		errChan <- err
		return
	}

	go forwardFromServerToClient()
	go forwardFromClientToServer()

	if err := <-errChan; err != nil && err.Error() != "EOF" {
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
			"] Redirect function returns, error: " + err.Error())
		return err
	}
	//TODO: don't print on graceful close
	return nil
}
