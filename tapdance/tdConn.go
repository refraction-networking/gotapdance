package tapdance

import (
	"time"
	"net"
	"strconv"
	"errors"
	"encoding/binary"
	"github.com/zmap/zgrab/ztools/ztls"
	"crypto/cipher"
	"bytes"
	"crypto/rand"
)

type tapdanceConn struct {
	ztlsConn         *ztls.Conn
	customDialer     *net.Dialer

	id               uint
	/* random per-connection (secret) id;
	 this way, the underlying SSL connection can disconnect
	 while the client's local conn and station's proxy conn
	 can stay connected */
	remoteConnId [16]byte

	winSize          uint16

	maxSend          uint64
	sentTotal        uint64

	initialized      bool
	reconnecting     bool
	toClose          bool // only Close, if MSG_CLOSE is received or timed out

	decoyHost        string
	decoyPort        int

	_read_buffer     []byte

	stationPubkey    *[32]byte
}

/* Create new TapDance connection
Args:
	id            -- only for logging and TapDance proxy, could be ignored
	customDialer  -- dial with customDialer, could be nil
 */
func DialTapDance(id uint, customDialer *net.Dialer) (tdConn *tapdanceConn, err error) {
	tdConn = new(tapdanceConn)

	tdConn.customDialer = customDialer
	tdConn.id = id
	tdConn.ztlsConn = nil

	tdConn.stationPubkey = &td_station_pubkey


	rand.Read(tdConn.remoteConnId[:])
	tdConn.initialized = false
	tdConn.reconnecting = false
	tdConn._read_buffer = make([]byte, 16 * 1024 + 20 + 20 + 12)
	// TODO: find better place for size, than From linux-2.6-stable/drivers/net/loopback.c
	err = tdConn.reconnect()
	return
}

func (tdConn *tapdanceConn) reconnect() (err error){

	if tdConn.initialized {
		tdConn.toClose = true
		tdConn.ztlsConn.Close()
		tdConn.toClose = false
		tdConn.initialized = false
	}
	tdConn.reconnecting = true
	defer func(){
		tdConn.reconnecting = false
		tdConn.sentTotal = 0
	}()

	tdConn.sentTotal = 0

	// Randomize tdConn.maxSend to avoid heuristics. Maybe it should be math.rand, though?
	rand_hextet := make([]byte, 2)
	rand.Read(rand_hextet)
	tdConn.maxSend = 16*1024 - uint64(binary.BigEndian.Uint16(rand_hextet[0:2]) % 1984) - 1
	// TODO: it's actually window size

	tdConn.decoyHost, tdConn.decoyPort = GenerateDecoyAddress()
	err = tdConn.establishTLStoDecoy()
	if err != nil {
		tdConn.toClose = true
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] establishTLStoDecoy() failed with " + err.Error())
		return
	} else {
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Connected to decoy " + tdConn.decoyHost)
	}

	var tdRequest string
	tdRequest, err = tdConn.prepareTDRequest()
	Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
		"] Prepared initial TD request:" + tdRequest)
	if err != nil {
		tdConn.toClose = true
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Preparation of initial TD request failed with " + err.Error())
		return
	}
	_, err = tdConn.Write([]byte(tdRequest))
	if err != nil {
		tdConn.toClose = true

		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Could not send initial TD request, error: " + err.Error())
		return
	}
	_, err = tdConn.Read(tdConn._read_buffer)
	if err != nil {
		tdConn.toClose = true
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] TapDance station didn't pick up the request. :(")
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Could not read from server after sending initial TD request, error: " +
			err.Error())
	}
	tdConn.sentTotal = 0
	return
}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (tdConn *tapdanceConn) Read(b []byte) (n int, err error) {
	// 1 byte of each message is MSG_TYPE
	// 2-3: length of message
	// if MSG_TYPE == INIT:
	//   4-5: magic_val
	//   6-7: window size
	// if MSG_TYPE == DATA:
	//    DATA
	// if MSG_TYPE == (CLOSE or RECONNECT):
	//    EOF
	var readBytesTotal uint16
	var readBytes int

	// Default timeout of 20 secs:
	tdConn.SetReadDeadline(time.Now().Add(time.Second * 20))

	for readBytesTotal < 3 {
		readBytes, err = tdConn.ztlsConn.Read(tdConn._read_buffer[readBytesTotal:])
		if tdConn.reconnecting && tdConn.initialized {
			time.Sleep(100 * time.Millisecond)
		} else {
			if err != nil {
				if err.Error() != "EOF" {
					tdConn.toClose = true
				}
				return
			}
			readBytesTotal += uint16(readBytes)
		}
	}
	var msgLen, magicVal, expectedMagicVal, winSize uint16
	var msgType uint8
	msgType = tdConn._read_buffer[0]
	msgLen = binary.BigEndian.Uint16(tdConn._read_buffer[1:3])

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
		readBytes, err = tdConn.ztlsConn.Read(tdConn._read_buffer[readBytesTotal:])
		if tdConn.reconnecting && tdConn.initialized {
			time.Sleep(100 * time.Millisecond)
		} else {
			if err != nil {
				if err.Error() != "EOF" {
					tdConn.toClose = true
				}
				return
			}
			readBytesTotal += uint16(readBytes)
		}
	}

	if msgType != MSG_INIT && tdConn.initialized == false {
		var actualType string
		if msgType == MSG_DATA {
			actualType = "Data message"
		} else if msgType == MSG_CLOSE {
			actualType = "Close Message"
		} else if msgType == MSG_RECONNECT {
			actualType = "Reconnect Message"
		} else {
			actualType = "Unknown Type Message " +
				strconv.FormatUint(uint64(msgType), 10)
		}
		err = errors.New("Expected INIT message, instead received: " + actualType)
	}
	if msgType == MSG_INIT && tdConn.initialized == true {
		err = errors.New("Received INIT message in initialized connection")
	}

	if msgType == MSG_INIT {
		magicVal = binary.BigEndian.Uint16(tdConn._read_buffer[3:5])
		winSize = binary.BigEndian.Uint16(tdConn._read_buffer[5:7])
		expectedMagicVal = uint16(0x2a75)
		if magicVal != expectedMagicVal {
			err = errors.New("INIT message: magic value mismatch! Expected: " +
				strconv.FormatUint(uint64(expectedMagicVal), 10) +
				", but received: " + strconv.FormatUint(uint64(magicVal), 10))
			return
		}
		tdConn.winSize = winSize
		tdConn.initialized = true
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10)  +
			"] Successfully connected to Tapdance Station!")
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10)  +
			"] Winsize = " + strconv.FormatUint(uint64(tdConn.winSize), 10))
		n = 0
	} else if msgType == MSG_DATA {
		n = int(readBytesTotal - headerSize)
		copy(b, tdConn._read_buffer[headerSize:readBytesTotal])
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10)  +
			"] Successfully read DATA msg from server: " + string(b))
	} else if msgType == MSG_CLOSE {
		tdConn.toClose = true
		err = errors.New("MSG_CLOSE")
	} else if msgType == MSG_RECONNECT {
		tdConn.reconnect()
	}
	return
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (tdConn *tapdanceConn) Write(b []byte) (n int, err error) {
	totalToSend := uint64(len(b))
	sentTotal := uint64(0)
	defer func(){n = int(sentTotal)}()
	// Default timeout of 20 secs:
	tdConn.SetWriteDeadline(time.Now().Add(time.Second * 20))

	for sentTotal != totalToSend {
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10)  +
			"] Already sent: " + strconv.FormatUint(tdConn.sentTotal, 10) +
			". Requested to send: " + strconv.FormatUint(totalToSend, 10))
		couldSend := tdConn.maxSend - tdConn.sentTotal
		if couldSend > totalToSend - sentTotal {
			_, err = tdConn.ztlsConn.Write(b[sentTotal:totalToSend])
			if err != nil {
				if tdConn.initialized && tdConn.reconnecting {
					time.Sleep(time.Second * 1)
				} else {
					tdConn.toClose = true
					return
				}
			}
			tdConn.sentTotal += (totalToSend - sentTotal)
			sentTotal = totalToSend
		} else {
			_, err = tdConn.ztlsConn.Write(b[sentTotal:sentTotal + couldSend])
			sentTotal += couldSend
			if err != nil {
				if tdConn.initialized && tdConn.reconnecting {
					time.Sleep(time.Second * 1)
					continue
				} else {
					tdConn.toClose = true
					return
				}
			}
			Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10)  +
				"] Sent maximum " + strconv.FormatUint(tdConn.maxSend + couldSend, 10) +
				" bytes. Reconnecting to Tapdance.")
			err = tdConn.reconnect()
			if err != nil {
				tdConn.toClose = true
				return
			}
		}
	}
	return
}


func (tdConn *tapdanceConn) establishTLStoDecoy() (err error) {
	//TODO: force stream cipher
	addr := tdConn.decoyHost + ":" + strconv.Itoa(tdConn.decoyPort)
	config := &ztls.Config{}
	if tdConn.customDialer != nil {
		ztls.DialWithDialer(tdConn.customDialer, "tcp", addr, config)
	} else {
		tdConn.ztlsConn, err = ztls.Dial("tcp", addr, config)
	}
	if err != nil {
		return
	}
	//Logger.Debugf("After establishing the TLS conn to Decoy: Connection is ", TDstate.servConn)
	return
}

func (tdConn *tapdanceConn) getKeystream(length int) []byte {
	// get current state of cipher and encrypt zeros to get keystream
	zeros := make([]byte, length)
	servConnCipher := tdConn.ztlsConn.OutCipher().(cipher.AEAD)
	keystreamWtag := servConnCipher.Seal(nil, tdConn.ztlsConn.OutSeq(), zeros, nil)
	return keystreamWtag[:length]
}


func (tdConn *tapdanceConn) prepareTDRequest() (tdRequest string, err error) {
	// Generate initial TapDance request
	buf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES

	master_key := tdConn.ztlsConn.GetHandshakeLog().KeyMaterial.MasterSecret.Value
	if _, err = buf.WriteString(initial_tag); err != nil {
		return
	}
	if err = binary.Write(buf, binary.BigEndian, uint8(len(master_key))); err != nil {
		return
	}
	buf.Write(master_key[:])
	buf.Write(tdConn.ServerRandom())
	buf.Write(tdConn.ClientRandom())
	buf.Write(tdConn.remoteConnId[:]) // connection id for persistence

	tag, err := obfuscateTag(buf.Bytes(), *tdConn.stationPubkey) // What we encode into the ciphertext
	if err != nil {
		return
	}
	//print_hex(tag, "tag")

	tdRequest = "GET / HTTP/1.1\r\nHost: www.example.cn\r\nX-Ignore: "
	keystreamOffset := len(tdRequest)
	//Logger.Debugf("tag", tag)
	keystreamSize := (len(tag) / 3  + 1) * 4 + keystreamOffset // we can't use first 2 bits of every byte
	whole_keystream := tdConn.getKeystream(keystreamSize)
	keystreamAtTag := whole_keystream[keystreamOffset:]
	//Logger.Debugf("keystream", keystream)
	//print_hex(keystream_at_tag, "keystream_at_tag")

	// req := "GET / HTTP/1.1\r\nHost:" + TDstate.decoy_host + "\r\nX-Ignore: "
	tdRequest += reverseEncrypt(tag, keystreamAtTag)
	Logger.Debugf("Prepared initial request to Decoy")//, td_request)

	return
}

func (tdConn *tapdanceConn) ClientRandom() []byte{
	return tdConn.ztlsConn.GetHandshakeLog().ClientHello.Random
}

func (tdConn *tapdanceConn) ServerRandom() []byte{
	return tdConn.ztlsConn.GetHandshakeLog().ServerHello.Random
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (tdConn *tapdanceConn) Close() (err error) {
	if tdConn.ztlsConn != nil{
		if tdConn.toClose {
			err = tdConn.ztlsConn.Close()
		} else {
			tdConn.reconnect()
		}
	}
	return
}

// LocalAddr returns the local network address.
func (tdConn *tapdanceConn) LocalAddr() net.Addr {
	return tdConn.ztlsConn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (tdConn *tapdanceConn) RemoteAddr() net.Addr {
	return tdConn.ztlsConn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future I/O, not just
// the immediately following call to Read or Write.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (tdConn *tapdanceConn) SetDeadline(t time.Time) error {
	return tdConn.ztlsConn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (tdConn *tapdanceConn) SetReadDeadline(t time.Time) error {
	return tdConn.ztlsConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (tdConn *tapdanceConn) SetWriteDeadline(t time.Time) error {
	return tdConn.ztlsConn.SetWriteDeadline(t)
}
