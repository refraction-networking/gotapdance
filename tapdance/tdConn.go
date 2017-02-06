package tapdance

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/zmap/zgrab/ztools/ztls"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type tapdanceConn struct {
	ztlsConn     *ztls.Conn
	customDialer func(string, string) (net.Conn, error)

	id uint
	/* random per-connection (secret) id;
	this way, the underlying SSL connection can disconnect
	while the client's local conn and station's proxy conn
	can stay connected */
	remoteConnId [16]byte

	winSize uint16

	maxSend   uint64
	sentTotal uint64

	initialized      int32
	reconnecting     int32
	reconnectingCond *sync.Cond

	decoyHost string
	decoyPort int

	_read_buffer []byte

	// read_data holds data between Read() calls when the
	// caller's buffer is to small to receive all the data
	// read in a message from the station.
	read_data_buffer []byte
	read_data_index  int
	read_data_count  int
	read_data_eof    bool

	stationPubkey *[32]byte
}

const (
	TD_USER_CALL = iota
	TD_INTERNAL_CALL
)

/* Create new TapDance connection
Args:
	id            -- only for logging and TapDance proxy, could be ignored
	customDialer  -- dial with customDialer, could be nil
*/
func DialTapDance(
	id uint,
	customDialer func(string, string) (net.Conn, error)) (tdConn *tapdanceConn, err error) {

	tdConn = new(tapdanceConn)

	tdConn.customDialer = customDialer
	tdConn.id = id
	tdConn.ztlsConn = nil

	tdConn.stationPubkey = &td_station_pubkey

	rand.Read(tdConn.remoteConnId[:])

	tdConn.initialized = 0
	tdConn.reconnecting = 0
	tdConn.reconnectingCond = sync.NewCond(new(sync.Mutex))

	tdConn._read_buffer = make([]byte, 16*1024+20+20+12)
	tdConn.read_data_buffer = make([]byte, 16*1024+20+20+12)
	// TODO: find better place for size, than From linux-2.6-stable/drivers/net/loopback.c
	err = tdConn.reconnect()
	return
}

func (tdConn *tapdanceConn) awaitReconnection() {
	Logger.Debug("await reconnection")
	tdConn.reconnectingCond.L.Lock()
	for atomic.LoadInt32(&tdConn.reconnecting) != 0 {
		tdConn.reconnectingCond.Wait()
	}
	tdConn.reconnectingCond.L.Unlock()
	Logger.Debug("done await reconnection")
}

func (tdConn *tapdanceConn) reconnect() (err error) {

	if !atomic.CompareAndSwapInt32(&tdConn.reconnecting, 0, 1) {
		// Reconnection is already in progress
		tdConn.awaitReconnection()
		return
	}

	if atomic.LoadInt32(&tdConn.initialized) != 0 {
		tdConn.ztlsConn.Close()
		atomic.StoreInt32(&tdConn.initialized, 0)
	}
	defer func() {
		tdConn.sentTotal = 0
		atomic.StoreInt32(&tdConn.initialized, 1)
		atomic.StoreInt32(&tdConn.reconnecting, 0)
		tdConn.reconnectingCond.Broadcast()
		Logger.Debug("broadcasted reconnection")
	}()

	tdConn.sentTotal = 0

	// Randomize tdConn.maxSend to avoid heuristics. Maybe it should be math.rand, though?
	rand_hextet := make([]byte, 2)
	rand.Read(rand_hextet)
	tdConn.maxSend = 16*1024 - uint64(binary.BigEndian.Uint16(rand_hextet[0:2])%1984) - 1
	// TODO: it's actually window size

	// TODO: when multiple decoy sites become available, cycle through them here
	tdConn.decoyHost, tdConn.decoyPort = GenerateDecoyAddress()
	err = tdConn.establishTLStoDecoy()
	if err != nil {
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
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Preparation of initial TD request failed with " + err.Error())
		return
	}
	_, err = tdConn.write_as([]byte(tdRequest), TD_INTERNAL_CALL)
	if err != nil {
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Could not send initial TD request, error: " + err.Error())
		return
	}
	_, err = tdConn.read_as(tdConn._read_buffer, TD_INTERNAL_CALL)
	if err != nil {
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
//
// TODO: doesn't yet support multiple concurrent Read() calls as
// required by https://golang.org/pkg/net/#Conn.
func (tdConn *tapdanceConn) Read(b []byte) (n int, err error) {
	if tdConn.read_data_count == 0 {
		if tdConn.read_data_eof {
			return 0, io.EOF
		}
		tdConn.read_data_count, err = tdConn.read_as(tdConn.read_data_buffer, TD_USER_CALL)
		tdConn.read_data_index = 0
		if err == io.EOF {
			tdConn.read_data_eof = true
			err = nil
		} else if err != nil {
			return 0, err
		}
	}
	n = tdConn.read_data_count
	if n > len(b) {
		n = len(b)
	}
	copy(b, tdConn.read_data_buffer[tdConn.read_data_index:tdConn.read_data_index+n])
	tdConn.read_data_index += n
	tdConn.read_data_count -= n
	return
}

func (tdConn *tapdanceConn) read_as(b []byte, caller int) (n int, err error) {
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

	if caller == TD_USER_CALL {
		// TapDance should NOT have a timeout, timeouts have to be handled by client and server
		// 3 hours timeout just to connect stale connections once in a (long) while
		tdConn.SetReadDeadline(time.Now().Add(time.Hour * 3))
	} else if caller == TD_INTERNAL_CALL {
		tdConn.SetReadDeadline(time.Now().Add(time.Second * 15))
	}

	for readBytesTotal < 3 {
		readBytes, err = tdConn.ztlsConn.Read(tdConn._read_buffer[readBytesTotal:])
		if caller == TD_USER_CALL && atomic.LoadInt32(&tdConn.reconnecting) != 0 {
			tdConn.awaitReconnection()
		} else {
			if err != nil {
				if (err.Error() == "EOF" ||
					strings.Contains(err.Error(), "connection reset by peer")) &&
					atomic.LoadInt32(&tdConn.initialized) != 0 {
					tdConn.reconnect()
					// TODO: think this moment through.
					// Won't we lose any data, sent by TD station?
				} else {
					return
				}
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
	for msgLen+headerSize < readBytesTotal {
		readBytes, err = tdConn.ztlsConn.Read(tdConn._read_buffer[readBytesTotal:])
		if caller == TD_USER_CALL && atomic.LoadInt32(&tdConn.reconnecting) != 0 {
			tdConn.awaitReconnection()
		} else {
			if err != nil {
				if (err.Error() == "EOF" ||
					strings.Contains(err.Error(), "connection reset by peer")) &&
					atomic.LoadInt32(&tdConn.initialized) != 0 {
					tdConn.reconnect()
				} else {
					return
				}
			}
			readBytesTotal += uint16(readBytes)
		}
	}

	if msgType != MSG_INIT && atomic.LoadInt32(&tdConn.initialized) == 0 {
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
	if msgType == MSG_INIT && atomic.LoadInt32(&tdConn.initialized) != 0 {
		err = errors.New("Received INIT message in initialized connection")
	} else if msgType == MSG_INIT {
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
		atomic.StoreInt32(&tdConn.initialized, 1)
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Successfully connected to Tapdance Station!")
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Winsize = " + strconv.FormatUint(uint64(tdConn.winSize), 10))
		n = 0
	} else if msgType == MSG_DATA {
		n = int(readBytesTotal - headerSize)
		copy(b, tdConn._read_buffer[headerSize:readBytesTotal])
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Successfully read DATA msg from server: " + string(b))
	} else if msgType == MSG_CLOSE {
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
	n, err = tdConn.write_as(b, TD_USER_CALL)
	return
}

func (tdConn *tapdanceConn) write_as(b []byte, caller int) (n int, err error) {
	totalToSend := uint64(len(b))
	sentTotal := uint64(0)
	defer func() { n = int(sentTotal) }()
	if caller == TD_USER_CALL {
		// TapDance should NOT have a timeout, timeouts have to be handled by client and server
		// 3 hours timeout just to connect stale connections once in a (long) while
		tdConn.SetWriteDeadline(time.Now().Add(time.Hour * 3))
	} else if caller == TD_INTERNAL_CALL {
		tdConn.SetWriteDeadline(time.Now().Add(time.Second * 15))
	}
	for sentTotal != totalToSend {
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Already sent: " + strconv.FormatUint(tdConn.sentTotal, 10) +
			". Requested to send: " + strconv.FormatUint(totalToSend, 10))
		couldSend := tdConn.maxSend - tdConn.sentTotal
		if couldSend > totalToSend-sentTotal {
			_, err = tdConn.ztlsConn.Write(b[sentTotal:totalToSend])
			if err != nil {
				if caller == TD_USER_CALL && atomic.LoadInt32(&tdConn.reconnecting) != 0 {
					tdConn.awaitReconnection()
					continue
				} else {
					return
				}
			}
			tdConn.sentTotal += (totalToSend - sentTotal)
			sentTotal = totalToSend
		} else {
			_, err = tdConn.ztlsConn.Write(b[sentTotal : sentTotal+couldSend])
			sentTotal += couldSend
			if err != nil {
				if caller == TD_USER_CALL && atomic.LoadInt32(&tdConn.reconnecting) != 0 {
					tdConn.awaitReconnection()
					continue
				} else {
					return
				}
			}
			Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] Sent maximum " + strconv.FormatUint(tdConn.maxSend, 10) +
				" bytes. Reconnecting to Tapdance.")
			err = tdConn.reconnect()
			if err != nil {
				return
			}
		}
	}
	return
}


// List of actually supported ciphers(not a list of offered ciphers!)
// Essentially all AES GCM ciphers, except for ANON and PSK
// ANON are too dangerous in our setting
// PSK might actually work, but are out of scope
// Maybe also get rid of DSS?
var TDSupportedCiphers = []uint16{
	ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
	ztls.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
	ztls.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
	ztls.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
}


func (tdConn *tapdanceConn) establishTLStoDecoy() (err error) {
	//TODO: force stream cipher
	addr := tdConn.decoyHost + ":" + strconv.Itoa(tdConn.decoyPort)
	config := getZtlsConfig("Firefox50")
	if tdConn.customDialer != nil {
		var dialConn net.Conn
		dialConn, err = tdConn.customDialer("tcp", addr)
		if err != nil {
			return
		}
		config.ServerName, _, err = net.SplitHostPort(addr)
		if err != nil {
			dialConn.Close()
			return
		}
		tdConn.ztlsConn = ztls.Client(dialConn, &config)
		err = tdConn.ztlsConn.Handshake()
		if err != nil {
			dialConn.Close()
			return
		}
	} else {
		tdConn.ztlsConn, err = ztls.Dial("tcp", addr, &config)
	}
	if err == nil {
		// TODO: move up
		cipher := tdConn.ztlsConn.ConnectionState().CipherSuite
		for _, c := range TDSupportedCiphers {
			if c == cipher {
				return
			}
		}
		err = errors.New("Unsupported cipher.")
		// TODO: send random traffic?
		tdConn.ztlsConn.Close()
	}
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

	// write flags
	if err = binary.Write(buf, binary.BigEndian, uint8(0)); err != nil {
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

	// Don't even need the following HTTP request
	// Ideally, it is never processed by decoy
	tdRequest = "GET / HTTP/1.1\r\n"
	tdRequest += "Host: tapdance.com\r\n"
	tdRequest += "X-Ignore: "

	tdRequest += getRandPadding(0, 750, 10)

	keystreamOffset := len(tdRequest)
	//Logger.Debugf("tag", tag)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	whole_keystream := tdConn.getKeystream(keystreamSize)
	keystreamAtTag := whole_keystream[keystreamOffset:]
	//Logger.Debugf("keystream", keystream)
	//print_hex(keystream_at_tag, "keystream_at_tag")

	// req := "GET / HTTP/1.1\r\nHost:" + TDstate.decoy_host + "\r\nX-Ignore: "
	tdRequest += reverseEncrypt(tag, keystreamAtTag)
	Logger.Debugf("Prepared initial request to Decoy") //, td_request)

	return
}

func (tdConn *tapdanceConn) ClientRandom() []byte {
	return tdConn.ztlsConn.GetHandshakeLog().ClientHello.Random
}

func (tdConn *tapdanceConn) ServerRandom() []byte {
	return tdConn.ztlsConn.GetHandshakeLog().ServerHello.Random
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (tdConn *tapdanceConn) Close() (err error) {
	if tdConn.ztlsConn != nil {
		err = tdConn.ztlsConn.Close()
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
