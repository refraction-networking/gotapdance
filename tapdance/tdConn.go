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
	"math"
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

	maxSend   uint64
	sentTotal uint64

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
	TD_INIT_CALL
	TD_RECONNECT_CALL
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

	tdConn.reconnecting = 0
	tdConn.reconnectingCond = sync.NewCond(new(sync.Mutex))

	tdConn._read_buffer = make([]byte, 16*1024+20+20+12)
	tdConn.read_data_buffer = make([]byte, 16*1024+20+20+12)
	// TODO: find better place for size, than From linux-2.6-stable/drivers/net/loopback.c
	err = tdConn.connect(TD_INIT_CALL)
	return
}

func (tdConn *tapdanceConn) awaitReconnection() {
	Logger.Debugf("await reconnection")
	tdConn.reconnectingCond.L.Lock()
	for atomic.LoadInt32(&tdConn.reconnecting) != 0 {
		tdConn.reconnectingCond.Wait()
	}
	tdConn.reconnectingCond.L.Unlock()
	Logger.Debugf("done await reconnection")
}

func (tdConn *tapdanceConn) connect(mode int) (err error) {
	if !atomic.CompareAndSwapInt32(&tdConn.reconnecting, 0, 1) {
		// Reconnection is already in progress
		tdConn.awaitReconnection()
		return
	}
	defer func() {
		tdConn.sentTotal = 0
		atomic.StoreInt32(&tdConn.reconnecting, 0)
		tdConn.reconnectingCond.Broadcast()
		Logger.Debugf("broadcasted reconnection")
	}()

	var connection_attempts int

	// Randomize tdConn.maxSend to avoid heuristics
	tdConn.maxSend = 16*1024 - uint64(getRandInt(1, 1984))

	switch mode {
	case TD_RECONNECT_CALL:
		tdConn.ztlsConn.Close()
		connection_attempts = 2
	case TD_INIT_CALL:
		connection_attempts = 6
	default:
		panic("tdConn.connect() was called with incorrect mode" + string(mode))
	}

	for i := 0; i < connection_attempts; i++ {
		if mode == TD_INIT_CALL {
			if i >= 2 {
				// sleep to prevent overwhelming decoy servers
				time.Sleep(time.Second * time.Duration(math.Pow(3, float64(i - 1))))
			}
			tdConn.decoyHost, tdConn.decoyPort = GenerateDecoyAddress()
		}

		err = tdConn.establishTLStoDecoy()
		if err != nil {
			Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] establishTLStoDecoy(" + tdConn.decoyHost +
				") failed with " + err.Error())
			continue
		} else {
			Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] Connected to decoy " + tdConn.decoyHost)
		}

		// Check if cipher is supported
		cipherIsSupported := func (id uint16)(bool) {
			for _, c := range TDSupportedCiphers {
				if c == id {
					return true
				}
			}
			return false
		}
		if !cipherIsSupported(tdConn.ztlsConn.ConnectionState().CipherSuite) {
			Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] decoy " + tdConn.decoyHost + ", offered unsupported cipher #" +
				strconv.FormatUint(uint64(tdConn.id), 10))
			err = errors.New("Unsupported cipher.")
			tdConn.ztlsConn.Close()
			continue
		}

		tdConn.SetReadDeadline(time.Now().Add(time.Second * 15))
		tdConn.SetWriteDeadline(time.Now().Add(time.Second * 15))

		var tdRequest string
		tdRequest, err = tdConn.prepareTDRequest()
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Prepared initial TD request:" + tdRequest)
		if err != nil {
			Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] Preparation of initial TD request failed with " + err.Error())
			tdConn.ztlsConn.Close()
			continue
		}
		tdConn.sentTotal = 0
		_, err = tdConn.write_as([]byte(tdRequest), mode)
		if err != nil {
			Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] Could not send initial TD request, error: " + err.Error())
			tdConn.ztlsConn.Close()
			continue
		}
		_, err = tdConn.read_as(tdConn._read_buffer, mode)
		if err != nil {
			str_err := err.Error()
			if strings.Contains(str_err, ": i/o timeout") || // client timed out
			   err.Error() == "EOF" { // decoy timed out
				err = errors.New("TapDance station didn't pick up the request")
				Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
					"] " + err.Error())
			} else {
				Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
					"] error reading from TapDance station :", err.Error())
			}
			tdConn.ztlsConn.Close()
			continue
		}

		// TapDance should NOT have a timeout, timeouts have to be handled by client and server
		// 3 hours timeout just to connect stale connections once in a (long) while
		tdConn.SetReadDeadline(time.Now().Add(time.Hour * 3))
		tdConn.SetWriteDeadline(time.Now().Add(time.Hour * 3))

		tdConn.sentTotal = 0
		return
	}
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
	// if MSG_TYPE == INIT or RECONNECT:
	//   4-5: magic_val
	// if MSG_TYPE == DATA:
	//    4-length: DATA

	var readBytesTotal, totalBytesToRead uint16
	var readBytes int
	var headerSize, msgLen, magicVal, expectedMagicVal uint16
	var msgType uint8
	headerSize = 3
	totalBytesToRead = 3
	n = 0

	for readBytesTotal < totalBytesToRead {
		readBytes, err = tdConn.ztlsConn.Read(tdConn._read_buffer[readBytesTotal:])
		if caller == TD_USER_CALL && atomic.LoadInt32(&tdConn.reconnecting) != 0 {
			tdConn.awaitReconnection()
		} else if err != nil {
			if (err.Error() == "EOF" ||
				strings.Contains(err.Error(), "connection reset by peer")) &&
				 caller == TD_USER_CALL {
				tdConn.connect(TD_RECONNECT_CALL)
				// TODO: think this moment through.
				// Won't we lose any data, sent by TD station?
			} else {
				return
			}
			readBytesTotal += uint16(readBytes)
		}
		if readBytesTotal >= headerSize && totalBytesToRead == headerSize {
			// once we read msg_len, add it to totalBytesToRead
			msgType = tdConn._read_buffer[0]
			msgLen = binary.BigEndian.Uint16(tdConn._read_buffer[1:3])
			totalBytesToRead = headerSize + msgLen
		}
	}

	switch msgType {
	case MSG_RECONNECT:
		if caller == TD_USER_CALL {
			err = errors.New("Received RECONNECT message in initialized connection")
		} else if caller == TD_INIT_CALL {
			err = errors.New("Received RECONNECT message instead of INIT!")
		}
		fallthrough
	case MSG_INIT:
		if caller == TD_USER_CALL {
			err = errors.New("Received INIT message in initialized connection")
		}
		if caller == TD_RECONNECT_CALL && msgType == MSG_INIT {
			// TODO: will be error eventually
			Logger.Warningf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] Got INIT instead of reconnect! Moving on")
		}
		magicVal = binary.BigEndian.Uint16(tdConn._read_buffer[3:5])
		expectedMagicVal = uint16(0x2a75)
		if magicVal != expectedMagicVal {
			err = errors.New("INIT message: magic value mismatch! Expected: " +
				strconv.FormatUint(uint64(expectedMagicVal), 10) +
				", but received: " + strconv.FormatUint(uint64(magicVal), 10))
			return
		}
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Successfully connected to Tapdance Station!")
	case MSG_DATA:
		n = int(readBytesTotal - headerSize)
		copy(b, tdConn._read_buffer[headerSize:readBytesTotal])
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Successfully read DATA msg from server: " + string(b))
	case MSG_CLOSE:
		err = errors.New("MSG_CLOSE")
	default:
		err = errors.New("Unknown message #" + strconv.FormatUint(uint64(msgType), 10))
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
			err = tdConn.connect(TD_RECONNECT_CALL)
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
	return
}

func (tdConn *tapdanceConn) getKeystream(length int) []byte {
	// get current state of cipher and encrypt zeros to get keystream
	zeros := make([]byte, length)
	// TODO: check for conversion error
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

	// Don't even need the following HTTP request
	// Ideally, it is never processed by decoy
	tdRequest = "GET / HTTP/1.1\r\n"
	tdRequest += "Host: " + tdConn.decoyHost + "\r\n"
	tdRequest += "X-Ignore: "

	tdRequest += getRandPadding(0, 750, 10)

	keystreamOffset := len(tdRequest)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	whole_keystream := tdConn.getKeystream(keystreamSize)
	keystreamAtTag := whole_keystream[keystreamOffset:]

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
