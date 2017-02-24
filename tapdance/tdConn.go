package tapdance

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/zmap/zgrab/ztools/ztls"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type tapdanceConn struct {
	tcpConn      *net.TCPConn
	ztlsConn     *ztls.Conn
	customDialer func(string, string) (net.Conn, error)

	id uint64
	/* random per-connection (secret) id;
	   this way, the underlying SSL connection can disconnect
	   while the client's local conn and station's proxy conn
	   can stay connected */
	remoteConnId [16]byte

	maxSend   uint64
	sentTotal uint64

	decoyHost string
	decoyPort int

	_readBuffer  []byte
	_writeBuffer []byte

	writeMsgSize  int
	writeMsgIndex int

	stationPubkey *[32]byte

	state int32
	err   error      // closing error
	errMu sync.Mutex // make it RWMutex and RLock on read?

	readChannel  chan []byte // HAVE TO BE NON-BLOCKING
	writeChannel chan []byte //

	readerTimeout <-chan time.Time
	writerTimeout <-chan time.Time

	// used by 2 engines to communicate /w one another
	// true is sent upon success
	readerStopped   chan bool
	doneReconnect   chan bool
	stopped         chan bool
	channelsStopped int32
}

const (
	TD_STATE_NEW = iota
	TD_STATE_CONNECTED
	TD_STATE_RECONNECT
	TD_STATE_CLOSED
)

const timeoutInSeconds = 30

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

	tdConn._readBuffer = make([]byte, 3) // Only read headers into it
	tdConn._writeBuffer = make([]byte, 16*1024+20+20+12)

	tdConn.stopped = make(chan bool)
	tdConn.readerStopped = make(chan bool)
	tdConn.doneReconnect = make(chan bool)
	tdConn.writeChannel = make(chan []byte, 1) // TODO: make it blocking?
	tdConn.readChannel = make(chan []byte, 1)

	tdConn.state = TD_STATE_NEW
	tdConn.connect()

	err = tdConn.err
	if err == nil {
		/* If connection was successful, TapDance launches 2 goroutines:
		first one handles sending of the data and does reconnection,
		second goroutine handles reading.
		*/
		go tdConn.readSubEngine()
		go tdConn.engineMain()
	}
	return
}

// Does writing to socket and reconnection
func (tdConn *tapdanceConn) engineMain() {
	defer func() {
		Logger.Debugln("[Flow " + tdConn.idStr() + "] exit engineMain()")
		close(tdConn.doneReconnect)
		tdConn.Close()
	}()

	for {
		switch atomic.LoadInt32(&tdConn.state) {
		case TD_STATE_RECONNECT:
			tdConn.tcpConn.CloseWrite()
			Logger.Debugln("[Flow " + tdConn.idStr() + "] write closed")
			tdConn.connect()
			continue
		case TD_STATE_CONNECTED:
		default:
			return
		}

		// If just reconnected, but still have user outgoing user data - send it
		if tdConn.writeMsgSize != 0 {
			_, _ = tdConn.write_td(tdConn._writeBuffer[tdConn.writeMsgIndex:tdConn.writeMsgSize], false)
			if atomic.LoadInt32(&tdConn.state) != TD_STATE_CONNECTED {
				continue
			}
		}

		select {
		case <-tdConn.stopped:
			return
		case <-tdConn.writerTimeout:
			// TODO <low priority>: check if any data was sent or received
			tdConn.tryScheduleReconnect()
			continue
		case tdConn._writeBuffer = <-tdConn.writeChannel:
			tdConn.writeMsgSize = len(tdConn._writeBuffer)
			_, err := tdConn.write_td(tdConn._writeBuffer[:tdConn.writeMsgSize], false)
			if err != nil {
				Logger.Debugln("[Flow " + tdConn.idStr() + "] write_td() " +
					"failed with " + err.Error())
				tdConn.setError(err, false)
				return
			}
		}
	}
}

// Reads from socket, sleeps during reconnection
func (tdConn *tapdanceConn) readSubEngine() {
	var err error
	defer func() {
		tdConn.setError(err, false)
		Logger.Debugln("[Flow " + tdConn.idStr() + "] exit readSubEngine()")
		close(tdConn.readerStopped)
		tdConn.Close()
	}()

	var toReconnect bool
	for {
		switch atomic.LoadInt32(&tdConn.state) {
		case TD_STATE_CONNECTED:
			if !toReconnect {
				break
			}
			tdConn.tryScheduleReconnect()
			fallthrough
		case TD_STATE_RECONNECT:
			if toReconnect {
				// Let main goroutine know read've stopped, enter barrier
				select {
				case <-tdConn.stopped:
					return
				case tdConn.readerStopped <- true:
				}

				select {
				case <-tdConn.stopped:
					return
				case okReconnect := <-tdConn.doneReconnect:
					if !okReconnect {
						return
					}
				}
				err = nil
				toReconnect = false
				continue
			}
		default:
			return
		}

		select {
		case <-tdConn.stopped:
			return
		case <-tdConn.readerTimeout:
			tdConn.tryScheduleReconnect()
			continue
		default:
			_, err = tdConn.read_msg(MSG_DATA)
			if err != nil {
				Logger.Debugln("[Flow "+tdConn.idStr()+"] read err", err)
				toReconnect = (err == io.EOF || err == io.ErrUnexpectedEOF)
				if nErr, ok := err.(*net.OpError); ok {
					if nErr.Err.Error() == "use of closed network connection" {
						toReconnect = true
					}
				}

				if toReconnect {
					continue
				} else {
					Logger.Debugln("[Flow " + tdConn.idStr() + "] read_msg() " +
						"failed with " + err.Error())
					return
				}
			}
		}
	}
}

func (tdConn *tapdanceConn) connect() {
	var reconnect bool
	// store current error, set it as connection-wide error if all attempts to connect failed
	currErr := errors.New("No connection attempts were made yet")

	defer func() {
		tdConn.sentTotal = 0
		_err := tdConn.getError()
		connectOk := (_err == nil)
		if connectOk {
			Logger.Debugf("[Flow " + tdConn.idStr() + "] connect success")
			atomic.StoreInt32(&tdConn.state, TD_STATE_CONNECTED)
		} else {
			Logger.Debugf("[Flow "+tdConn.idStr()+"] connect fail", _err)
			atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
		}
		if reconnect {
			select {
			case tdConn.doneReconnect <- connectOk:
			case <-tdConn.stopped:
			}

		}
	}()

	switch atomic.LoadInt32(&tdConn.state) {
	case TD_STATE_RECONNECT:
		reconnect = true
	case TD_STATE_NEW:
		reconnect = false
	case TD_STATE_CONNECTED:
		Logger.Errorf("Flow " + tdConn.idStr() + "] called reconnect" +
			", but state is TD_STATE_CONNECTED")
	case TD_STATE_CLOSED:
		Logger.Errorf("Flow " + tdConn.idStr() + "] called reconnect" +
			"but state is TD_STATE_CLOSED")
	default:
		Logger.Errorf("Flow " + tdConn.idStr() + "] called reconnect" +
			"but state is garbage: " + strconv.FormatUint(uint64(tdConn.state), 10))
	}

	var expectedMsg uint8
	var connection_attempts int

	// Randomize tdConn.maxSend to avoid heuristics
	tdConn.maxSend = 16*1024 - uint64(getRandInt(1, 1984))

	if reconnect {
		connection_attempts = 2
		expectedMsg = MSG_RECONNECT
		select {
		case _ = <-tdConn.readerStopped: // wait for readEngine to stop
		case <-tdConn.stopped:
			return
		}
		tdConn.ztlsConn.Close()
	} else {
		connection_attempts = 6
		expectedMsg = MSG_INIT
	}

	for i := 0; i < connection_attempts; i++ {
		if !reconnect {
			if i >= 2 {
				// sleep to prevent overwhelming decoy servers
				waitTime := time.After(time.Second *
					time.Duration(math.Pow(3, float64(i-1))))
				select {
				case <-waitTime:
				case <-tdConn.stopped:
					return
				}
			}
			tdConn.decoyHost, tdConn.decoyPort = GenerateDecoyAddress()
		}

		currErr = tdConn.establishTLStoDecoy()
		if currErr != nil {
			Logger.Errorf("[Flow " + tdConn.idStr() +
				"] establishTLStoDecoy(" + tdConn.decoyHost +
				") failed with " + currErr.Error())
			continue
		} else {
			Logger.Infof("[Flow " + tdConn.idStr() +
				"] Connected to decoy " + tdConn.decoyHost)
		}

		// Check if cipher is supported
		cipherIsSupported := func(id uint16) bool {
			for _, c := range TDSupportedCiphers {
				if c == id {
					return true
				}
			}
			return false
		}
		if !cipherIsSupported(tdConn.ztlsConn.ConnectionState().CipherSuite) {
			Logger.Errorf("[Flow " + tdConn.idStr() +
				"] decoy " + tdConn.decoyHost + ", offered unsupported cipher #" +
				strconv.FormatUint(uint64(tdConn.id), 10))
			currErr = errors.New("Unsupported cipher.")
			tdConn.ztlsConn.Close()
			continue
		}

		tdConn.SetDeadline(time.Now().Add(time.Second * 15))

		var tdRequest string
		tdRequest, currErr = tdConn.prepareTDRequest()
		Logger.Debugf("[Flow " + tdConn.idStr() +
			"] Prepared initial TD request:" + tdRequest)
		if currErr != nil {
			Logger.Errorf("[Flow " + tdConn.idStr() +
				"] Preparation of initial TD request failed with " + currErr.Error())
			tdConn.ztlsConn.Close()
			continue
		}

		tdConn.sentTotal = 0
		_, currErr = tdConn.write_td([]byte(tdRequest), true)
		if currErr != nil {
			Logger.Errorf("[Flow " + tdConn.idStr() +
				"] Could not send initial TD request, error: " + currErr.Error())
			tdConn.ztlsConn.Close()
			continue
		}

		_, currErr = tdConn.read_msg(expectedMsg)
		if currErr != nil {
			str_err := currErr.Error()
			if strings.Contains(str_err, ": i/o timeout") || // client timed out
				currErr.Error() == "EOF" {
				// decoy timed out
				currErr = errors.New("TapDance station didn't pick up the request")
				Logger.Errorf("[Flow " + tdConn.idStr() +
					"] " + currErr.Error())
			} else {
				Logger.Errorf("[Flow "+tdConn.idStr()+
					"] error reading from TapDance station :", currErr.Error())
			}
			tdConn.ztlsConn.Close()
			continue
		}

		// TapDance should NOT have a timeout, timeouts have to be handled by client and server
		// 3 hours timeout just to connect stale connections once in a (long) while
		tdConn.SetDeadline(time.Now().Add(time.Hour * 3))

		tdConn.writerTimeout = time.After(timeoutInSeconds * time.Second)
		// reader shouldn't timeout yet
		tdConn.readerTimeout = time.After(1 * time.Hour)

		tdConn.sentTotal = 0
		return
	}
	tdConn.setError(currErr, false)
	return
}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (tdConn *tapdanceConn) Read(b []byte) (n int, err error) {
	// TODO: FIX THAT EMBARRASSMENT
	// Buffer is reallocated and recopied twice!
	// If len(b) < 1500, then things will break
	// But now Read() could be invoked by multiple goroutines, hooray(no)
	// Golang doesn't let me do 'b = <-tdConn.readChannel' =/
	defer func() {
		if n == 0 {
			err = tdConn.getError()
		}
	}()
	for {
		chanTimeout := time.After(3 * time.Second)
		select {
		case bb := <-tdConn.readChannel:
			n = len(bb)
			if n != 0 {
				copy(b, bb)
			}
			return
		case <-chanTimeout:
			select {
			case <-tdConn.stopped:
				return
			default:
			}
		}
	}
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
	defer func() { n = int(readBytesTotal) }()

	var msgLen uint16
	var msgType uint8

	// This function checks if message type, given particular caller, is appropriate.
	// In case it is appropriate - returns nil, otherwise - the error
	checkMsgType := func(_actualMsg uint8, _expectedMsg uint8) error {
		switch _actualMsg {
		case MSG_RECONNECT:
			if _expectedMsg == MSG_DATA {
				return errors.New("Received unexpected RECONNECT message")
			} else if _expectedMsg == MSG_INIT {
				return errors.New("Received RECONNECT message instead of INIT")
			}
		case MSG_INIT:
			if _expectedMsg == MSG_DATA {
				return errors.New("Received INIT message in initialized connection")
			}
			if _expectedMsg == MSG_RECONNECT {
				return errors.New("Received INIT message instead of RECONNECT")
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
		readBytes, err = tdConn.ztlsConn.Read(tdConn._readBuffer[readBytesTotal:headerSize])
		if err != nil {
			return
		}
		readBytesTotal += uint16(readBytes)
	}

	// Check if the message type is appropriate
	msgType = tdConn._readBuffer[0]
	err = checkMsgType(msgType, expectedMsg)
	if err != nil {
		return
	}

	// Add msgLen to totalBytesToRead
	msgLen = binary.BigEndian.Uint16(tdConn._readBuffer[1:3])
	totalBytesToRead = headerSize + msgLen
	read_buffer := make([]byte, msgLen)

	// Get the rest of the message
	for readBytesTotal < totalBytesToRead {
		readBytes, err = tdConn.ztlsConn.Read(read_buffer[readBytesTotal-headerSize : msgLen])
		if err != nil {
			return
		}
		readBytesTotal += uint16(readBytes)
	}

	//	Logger.Debugln("[Flow " + tdConn.idStr() + "] read\n", hex.Dump(read_buffer[:totalBytesToRead]))

	// Process actual message
	switch msgType {
	case MSG_RECONNECT:
		fallthrough
	case MSG_INIT:
		var magicVal, expectedMagicVal uint16
		if len(read_buffer) < 2 {
			err = errors.New("Message body too short!")
			return
		}
		magicVal = binary.BigEndian.Uint16(read_buffer[:2])
		expectedMagicVal = uint16(0x2a75)
		if magicVal != expectedMagicVal {
			err = errors.New("Magic value mismatch! Expected: " +
				strconv.FormatUint(uint64(expectedMagicVal), 10) +
				", but received: " + strconv.FormatUint(uint64(magicVal), 10))
			return
		}
		Logger.Infof("[Flow " + tdConn.idStr() +
			"] Successfully connected to Tapdance Station!")
	case MSG_DATA:
		n = int(readBytesTotal - headerSize)
		select {
		case tdConn.readChannel <- read_buffer[:]:
			Logger.Debugf("[Flow "+tdConn.idStr()+
				"] Successfully read DATA msg from server", msgLen)
		case <-tdConn.stopped:
			return
			// TODO: add reconnect here?
		}
	case MSG_CLOSE:
		err = errors.New("MSG_CLOSE")
		Logger.Infof("[Flow " + tdConn.idStr() +
			"] received MSG_CLOSE")
	}
	return
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (tdConn *tapdanceConn) Write(b []byte) (n int, err error) {
	// TODO: why does it break if I don't make a copy here?
	bb := make([]byte, len(b))
	copy(bb, b)
	select {
	case tdConn.writeChannel <- bb:
		n = len(bb)
	case <-tdConn.stopped:
	}
	if n == 0 {
		err = tdConn.getError()
	}
	return
}

func (tdConn *tapdanceConn) write_td(b []byte, connect bool) (n int, err error) {
	totalToSend := uint64(len(b))

	Logger.Debugf("[Flow " + tdConn.idStr() +
		"] Already sent: " + strconv.FormatUint(tdConn.sentTotal, 10) +
		". Requested to send: " + strconv.FormatUint(totalToSend, 10))
	if !connect {
		defer func() {
			tdConn.sentTotal += uint64(n)
			if tdConn.writeMsgIndex >= tdConn.writeMsgSize {
				tdConn.writeMsgIndex = 0
				tdConn.writeMsgSize = 0
			}
		}()
	}

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
		tdConn.tryScheduleReconnect()
		if tdConn.sentTotal != 0 {
			// reconnect right away
			Logger.Infof("[Flow " + tdConn.idStr() +
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

	// TODO: why does it break if I don't make a copy here?
	bb := make([]byte, toSend)

	copy(bb, b)
	n, err = tdConn.ztlsConn.Write(bb[:])

	if !connect {
		tdConn.writeMsgIndex += n
	}

	if err != nil {
		atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
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
	addr := tdConn.decoyHost + ":" + strconv.Itoa(tdConn.decoyPort)
	config := getZtlsConfig("Firefox50")
	var dialConn net.Conn
	if tdConn.customDialer != nil {
		dialConn, err = tdConn.customDialer("tcp", addr)
		if err != nil {
			return err
		}
	} else {
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return err
		}
		dialConn, err = net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return err
		}
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
	tdConn.tcpConn = dialConn.(*net.TCPConn)
	return
}

// get current state of cipher and encrypt zeros to get keystream
func (tdConn *tapdanceConn) getKeystream(length int) (keystream []byte, err error) {
	zeros := make([]byte, length)

	if servConnCipher, ok := tdConn.ztlsConn.OutCipher().(cipher.AEAD); ok {
		keystream = servConnCipher.Seal(nil, tdConn.ztlsConn.OutSeq(), zeros, nil)
		return
	} else {
		err = errors.New("Could not convert ztlsConn.OutCipher to cipher.AEAD")
	}
	return
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
	whole_keystream, err := tdConn.getKeystream(keystreamSize)
	if err != nil {
		return
	}
	keystreamAtTag := whole_keystream[keystreamOffset:]

	tdRequest += reverseEncrypt(tag, keystreamAtTag)
	Logger.Debugf("Prepared initial request to Decoy") //, td_request)

	return
}

func (tdConn *tapdanceConn) idStr() string {
	return strconv.FormatUint(uint64(tdConn.id), 10)
}

func (tdConn *tapdanceConn) setError(err error, overwrite bool) {
	if err == nil {
		return
	}
	tdConn.errMu.Lock()
	defer tdConn.errMu.Unlock()
	if tdConn.err != nil && !overwrite {
		return
	} else {
		tdConn.err = err
	}

}

func (tdConn *tapdanceConn) getError() (err error) {
	tdConn.errMu.Lock()
	defer tdConn.errMu.Unlock()
	return tdConn.err
}

func (tdConn *tapdanceConn) tryScheduleReconnect() {
	for {
		switch atomic.LoadInt32(&tdConn.state) {
		case TD_STATE_CONNECTED:
			_ = atomic.CompareAndSwapInt32(&tdConn.state,
				TD_STATE_CONNECTED, TD_STATE_RECONNECT)
		default:
			return
		}
	}
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
	tdConn.setError(errors.New("Forced shutdown by user"), false)
	if atomic.CompareAndSwapInt32(&tdConn.channelsStopped, 0, 1) {
		close(tdConn.stopped)
		atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
	}
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
