package tapdance

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/zmap/zgrab/ztools/ztls"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"math"
	"encoding/hex"
	"runtime"
)

type tapdanceConn struct {
	ztlsConn         *ztls.Conn
	customDialer     func(string, string) (net.Conn, error)

	id               uint64
				   /* random per-connection (secret) id;
				   this way, the underlying SSL connection can disconnect
				   while the client's local conn and station's proxy conn
				   can stay connected */
	remoteConnId     [16]byte

	maxSend          uint64
	sentTotal        uint64

	decoyHost        string
	decoyPort        int

	_readBuffer      []byte
	_writeBuffer     []byte

	writeMsgSize     int
	writeMsgIndex    int

	stationPubkey    *[32]byte

	state            int32
	err              error // closing error

	readChannel      chan []byte // HAVE TO BE NON-BLOCKING
	writeChannel     chan []byte //

	// used by 2 engines to communicate /w one another
	// true is sent upon success
	stopSyncChan     chan bool
}

const (
	TD_STATE_NEW = iota
	TD_STATE_CONNECTED
	TD_STATE_RECONNECT
	TD_STATE_CLOSED
)

/* Create new TapDance connection
Args:
	id            -- only for logging and TapDance proxy, could be ignored
	customDialer  -- dial with customDialer, could be nil
*/
func DialTapDance(
	id uint64,
	customDialer func(string, string) (net.Conn, error)) (tdConn *tapdanceConn, err error) {

	tdConn = new(tapdanceConn)

	tdConn.customDialer = customDialer
	tdConn.id = id
	tdConn.ztlsConn = nil

	tdConn.stationPubkey = &td_station_pubkey

	rand.Read(tdConn.remoteConnId[:])

	// TODO: find better place for size, than From linux-2.6-stable/drivers/net/loopback.c
	tdConn._readBuffer = make([]byte, 16*1024+20+20+12)
	tdConn._writeBuffer = make([]byte, 16*1024+20+20+12)

	tdConn.stopSyncChan = make(chan bool)
	tdConn.writeChannel = make(chan []byte, 1)
	tdConn.readChannel = make(chan []byte, 1)

	tdConn.state = TD_STATE_NEW
	tdConn.connect()
	err = tdConn.err
	if err == nil {
		go tdConn.readSubEngine()
		go tdConn.engineMain()
	}
	return
}

func (tdConn *tapdanceConn) engineMain() {
	// Does writing to socket and (re)connection
	defer func() {
		tdConn.Close()
	}()

	for {
		switch atomic.LoadInt32(&tdConn.state) {
		case TD_STATE_RECONNECT: tdConn.connect()

		case TD_STATE_CONNECTED:
			if tdConn.writeMsgSize != 0 {
				_, _ = tdConn.write_td(tdConn._writeBuffer[tdConn.writeMsgIndex:tdConn.writeMsgSize])
				if atomic.LoadInt32(&tdConn.state) != TD_STATE_CONNECTED {
					continue
				}
			}
			select {
			case tdConn._writeBuffer = <-tdConn.writeChannel:
				tdConn.writeMsgSize = len(tdConn._writeBuffer)
				_, _ = tdConn.write_td(tdConn._writeBuffer[:tdConn.writeMsgSize])
			}

		case TD_STATE_NEW: fallthrough
		case TD_STATE_CLOSED: fallthrough
		default: return
		}
		runtime.Gosched()
	}
}


func (tdConn *tapdanceConn) readSubEngine() {
	for {
		switch atomic.LoadInt32(&tdConn.state) {
		case TD_STATE_CONNECTED:
			_, _ = tdConn.read_msg(MSG_DATA)
		// Reads from socket, writes to channel
		case TD_STATE_CLOSED:
			return
		case TD_STATE_RECONNECT:
			// Let main goroutine know read've stopped, enter barrier
			tdConn.stopSyncChan <- true
			okReconnect := <-tdConn.stopSyncChan
			if !okReconnect {
				break
			}
		default: panic("Corrupted state")
		}
		runtime.Gosched()
	}
}


func (tdConn *tapdanceConn) connect() {
	var reconnect bool
	defer func() {
		tdConn.sentTotal = 0
		connectOk := (tdConn.err == nil)
		if connectOk{
			atomic.StoreInt32(&tdConn.state, TD_STATE_CONNECTED)
		} else {
			atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
		}
		if reconnect {
			tdConn.stopSyncChan <- connectOk
		}
	}()

	switch tdConn.state {
	case TD_STATE_RECONNECT: reconnect = true
	case TD_STATE_NEW: reconnect = false
	case TD_STATE_CONNECTED: panic("reconnect was called, but state is TD_STATE_CONNECTED")
	case TD_STATE_CLOSED: panic("reconnect was called, but state is TD_STATE_CLOSED")
	default: panic("reconnect was called, but state is garbage: " +
		strconv.FormatUint(uint64(tdConn.state), 10))
	}

	var expectedMsg uint8
	var connection_attempts int

	// Randomize tdConn.maxSend to avoid heuristics
	tdConn.maxSend = 16*1024 - uint64(getRandInt(1, 1984))

	if reconnect {
		tdConn.ztlsConn.Close()
		connection_attempts = 2
		expectedMsg = MSG_RECONNECT
		_ = <-tdConn.stopSyncChan // wait for readEngine to stop
	} else {
		connection_attempts = 6
		expectedMsg = MSG_INIT
	}

	// store current error, set it as connection-wide error if all attempts to connect failed
	currErr := errors.New("No connection attempts were made yet")
	for i := 0; i < connection_attempts; i++ {
		if !reconnect {
			if i >= 2 {
				// sleep to prevent overwhelming decoy servers
				waitTime := time.After(time.Second *
					time.Duration(math.Pow(3, float64(i - 1))))
				for {
					select {
					// Got a timeout! fail with a timeout error
					case <-waitTime:
						break
					// Got a tick, we should check on doSomething()
					case <-tdConn.stopSyncChan:
						return
					}
					time.Sleep(0)
				}
			}
			tdConn.decoyHost, tdConn.decoyPort = GenerateDecoyAddress()
		}

		currErr = tdConn.establishTLStoDecoy()
		if currErr != nil {
			Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] establishTLStoDecoy(" + tdConn.decoyHost +
				") failed with " + currErr.Error())
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
			currErr = errors.New("Unsupported cipher.")
			tdConn.ztlsConn.Close()
			continue
		}

		tdConn.SetReadDeadline(time.Now().Add(time.Second * 15))
		tdConn.SetWriteDeadline(time.Now().Add(time.Second * 15))

		var tdRequest string
		tdRequest, currErr = tdConn.prepareTDRequest()
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Prepared initial TD request:" + tdRequest)
		if currErr != nil {
			Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] Preparation of initial TD request failed with " + currErr.Error())
			tdConn.ztlsConn.Close()
			continue
		}

		tdConn.sentTotal = 0
		_, currErr = tdConn.write_td([]byte(tdRequest))
		if currErr != nil {
			Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] Could not send initial TD request, error: " + currErr.Error())
			tdConn.ztlsConn.Close()
			continue
		}

		_, currErr = tdConn.read_msg(expectedMsg)
		if currErr != nil {
			str_err := currErr.Error()
			if strings.Contains(str_err, ": i/o timeout") || // client timed out
				currErr.Error() == "EOF" { // decoy timed out
				currErr = errors.New("TapDance station didn't pick up the request")
				Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
					"] " + currErr.Error())
			} else {
				Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
					"] error reading from TapDance station :", currErr.Error())
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
	tdConn.err = currErr
	return
}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
//
// TODO: doesn't yet support multiple concurrent Read() calls as
// required by https://golang.org/pkg/net/#Conn.
func (tdConn *tapdanceConn) Read(b []byte) (n int, err error) {
	bb := <-tdConn.readChannel
	n = len(bb)
	if n != 0 {
		copy(b, bb)
	}
	err = tdConn.err
	return
}

func (tdConn *tapdanceConn) read_msg(expectedMsg uint8) (n int, err error) {
	// 1 byte of each message is MSG_TYPE
	// 2-3: length of message
	// if MSG_TYPE == INIT or RECONNECT:
	//   4-5: magic_val
	// if MSG_TYPE == DATA:
	//    4-length: DATA

	var readBytes int
	var readBytesTotal uint16
	headerSize := uint16(3)
	totalBytesToRead := headerSize

	var msgLen uint16
	var msgType uint8

	headerIsRead := false

	// Read into special buffer, if it is connect/reconnect
	var read_buffer []byte
	switch expectedMsg {
	case MSG_RECONNECT: fallthrough
	case MSG_INIT: read_buffer = make([]byte, 4096)
	case MSG_DATA: read_buffer = tdConn._readBuffer[:]
	default: panic("tdConn.read_msg was called with incorrect msg " + string(expectedMsg))
	}

	// This function checks if message type, given particular caller, is appropriate.
	// In case it is appropriate - returns nil, otherwise - the error
	checkMsgType := func(_actualMsg uint8, _expectedMsg uint8) (error) {
		switch _actualMsg {
		case MSG_RECONNECT:
			if _expectedMsg == MSG_DATA {
				return errors.New("Received RECONNECT message in initialized connection")
			} else if _expectedMsg == MSG_INIT {
				return errors.New("Received RECONNECT message instead of INIT!")
			}
		case MSG_INIT:
			if _expectedMsg == MSG_DATA {
				return errors.New("Received INIT message in initialized connection")
			}
			if _expectedMsg == MSG_RECONNECT {
				// TODO: will be error eventually
				Logger.Warningf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
					"] Got INIT instead of reconnect! Moving on")
			}
		case MSG_DATA:
			if _expectedMsg == MSG_RECONNECT || _expectedMsg == MSG_INIT {
				return errors.New("Received DATA message in uninitialized connection")
			}
		case MSG_CLOSE:
			// always appropriate
		default:
			return errors.New("Unknown message #" + strconv.FormatUint(uint64(_actualMsg), 10))
		}
		return nil
	}

	for readBytesTotal < totalBytesToRead {
		readBytes, err = tdConn.ztlsConn.Read(read_buffer[readBytesTotal:totalBytesToRead])
		if err != nil {
			if (err.Error() == "EOF" ||
			    strings.Contains(err.Error(), "read: connection reset by peer")) &&
			    expectedMsg == MSG_DATA {
				// TODO: is there a better check?

				// TODO: check for whether any data was succesfully sent
				// If not -- don't reconnect, just rotate
				Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
					"] triggered reconnect in Read()")
				if atomic.CompareAndSwapInt32(&tdConn.state,
					TD_STATE_CONNECTED, TD_STATE_RECONNECT) {
					tdConn.stopSyncChan <- true
					reconnectOk := <-tdConn.stopSyncChan
					if reconnectOk {
						break
					} else {
						return
					}
				} else if atomic.LoadInt32(&tdConn.state) == TD_STATE_RECONNECT {
					tdConn.stopSyncChan <- true
					reconnectOk := <-tdConn.stopSyncChan
					if reconnectOk {
						break
					} else {
						return
					}
				} else {
					return
				}
			} else { // non-nil unacceptable error
				return
				}
		}
		readBytesTotal += uint16(readBytes)

		if readBytesTotal >= headerSize && !headerIsRead {
			// Once we read the header
			headerIsRead = true

			// Check if the message type is appropriate
			msgType = read_buffer[0]
			err = checkMsgType(msgType, expectedMsg)
			if err != nil {
				return
			}

			// Add msgLen to totalBytesToRead
			msgLen = binary.BigEndian.Uint16(read_buffer[1:3])
			totalBytesToRead = headerSize + msgLen
		}
	}

	// Process actual message
	switch msgType {
	case MSG_RECONNECT:
		fallthrough
	case MSG_INIT:
		var magicVal, expectedMagicVal uint16
		magicVal = binary.BigEndian.Uint16(read_buffer[3:5])
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
		tdConn.readChannel <- read_buffer[headerSize:readBytesTotal]
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] Successfully read DATA msg from server: \n" +
			hex.Dump(read_buffer[headerSize:readBytesTotal]))
	case MSG_CLOSE:
		err = errors.New("MSG_CLOSE")
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
			"] received MSG_CLOSE")
	}
	return
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (tdConn *tapdanceConn) Write(b []byte) (n int, err error) {
	tdConn.writeChannel <- b
	err = tdConn.err
	if err == nil {
		n = len(b)
	}
	return
}

func (tdConn *tapdanceConn) write_td(b []byte) (n int, err error) {
	totalToSend := uint64(len(b))

	Logger.Debugf("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
		"] Already sent: " + strconv.FormatUint(tdConn.sentTotal, 10) +
		". Requested to send: " + strconv.FormatUint(totalToSend, 10))
	defer func() {
		tdConn.sentTotal += uint64(n)
		if tdConn.writeMsgIndex >= tdConn.writeMsgSize {
			tdConn.writeMsgIndex = 0
			tdConn.writeMsgSize = 0
		}
	}()

	couldSend := tdConn.maxSend - tdConn.sentTotal
	toSend := uint64(0) // to send on this iteration
	/*
	/ Check if we are able to send the whole buffer or not(due to 16kB upload limit).
	/ We may want to split buffer into 2 or more chunks and send them chunk by chunk
	/ after reconnect(s). Unfortunately, we can't just always split it, as some
	/ protocols don't allow fragmentation, e.g. ssh: it sets goddamn IPv4
	/ 'Don't Fragment' flag and will break, if you force fragmentation.
	/ And we don't really know which application is using TapDance: ssh-style or
	/ Extra-Jumbo-Frame-Over-16kB-style.
	/ That's why we will only fragment, if 0 bytes were sent in this connection, but
	/ data still doesn't fit. This way we will accommodate all.
	*/
	needReconnect := (couldSend < totalToSend)
	if needReconnect {
		atomic.StoreInt32(&tdConn.state, TD_STATE_RECONNECT)
		if tdConn.sentTotal != 0 {
			// reconnect right away
			Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdConn.id), 10) +
				"] triggered preemptive reconnect in Write()")
			return
		} else {
			// split buffer in chunks and reconnect after
			toSend = couldSend
		}
	} else {
		// can send everything
		toSend = totalToSend
	}

	n, err = tdConn.ztlsConn.Write(b[:toSend])
	tdConn.writeMsgIndex += n
	if err != nil {
		if (err.Error() == "EOF" ||
			strings.Contains(err.Error(), "connection reset by peer")) {
			for {
				switch atomic.LoadInt32(&tdConn.state) {
				case TD_STATE_CONNECTED:
					if atomic.CompareAndSwapInt32(&tdConn.state,
					TD_STATE_CONNECTED, TD_STATE_RECONNECT) {
						return
					}
				case TD_STATE_RECONNECT: fallthrough
				case TD_STATE_NEW: fallthrough
				case TD_STATE_CLOSED: return
				default: panic("Corrupted state")
				}
				runtime.Gosched()
			}
		} else {
			atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
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
	// TODO: tdConn.err might remain nil
	close(tdConn.stopSyncChan)
	close(tdConn.writeChannel)
	close(tdConn.readChannel)
	atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
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
