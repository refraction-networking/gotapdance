package tapdance

import (
	"github.com/golang/protobuf/proto"
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/zmap/zcrypto/tls"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type tapdanceConn struct {
	tcpConn           *net.TCPConn
	tlsConn           *tls.Conn
	customDialer      func(string, string) (net.Conn, error)

	id                uint64
				      /* random per-connection (secret) id;
					 this way, the underlying SSL connection can disconnect
					 while the client's local conn and station's proxy conn
					 can stay connected */
	remoteConnId      [16]byte

	maxSend           uint64
	sentTotal         uint64

	decoyAddr         string      // ipv4_addr:port
	decoySNI          string

	_readBuffer       []byte
	_writeBuffer      []byte

	writeMsgSize      int
	writeMsgIndex     int

	stationPubkey     *[32]byte

	state             int32
	err               error       // closing error
	errMu             sync.Mutex  // make it RWMutex and RLock on read?

	readChannel       chan []byte // HAVE TO BE NON-BLOCKING
	writeChannel      chan []byte //

	readerTimeout     <-chan time.Time
	writerTimeout     <-chan time.Time

				      // used by 2 engines to communicate /w one another
				      // true is sent upon success
	readerStopped     chan bool
	doneReconnect     chan bool
	stopped           chan bool
	closeOnce         sync.Once

				      // read_data holds data between Read() calls when the
				      // caller's buffer is to small to receive all the data
				      // read in a message from the station.
	read_data_buffer  []byte
	read_data_index   int
	read_data_count   int

				      // for statistics
	writeReconnects   int
	timeoutReconnects int
}

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
	tdConn.tlsConn = nil

	tdConn.stationPubkey = Assets().GetPubkey()

	rand.Read(tdConn.remoteConnId[:])

	tdConn._readBuffer = make([]byte, 3) // Only read headers into it
	tdConn._writeBuffer = make([]byte, 16 * 1024 + 20 + 20 + 12)

	tdConn.read_data_buffer = make([]byte, 2024)

	tdConn.stopped = make(chan bool)
	tdConn.readerStopped = make(chan bool)
	tdConn.doneReconnect = make(chan bool)
	tdConn.writeChannel = make(chan []byte)
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
			Logger.Infoln("[Flow " + tdConn.idStr() + "] reconnecting!" +
				" write_total: " + strconv.Itoa(tdConn.writeReconnects) +
				" timeout_total: " + strconv.Itoa(tdConn.timeoutReconnects))
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
			tdConn.timeoutReconnects++
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
		tdConn.Close()
		close(tdConn.readerStopped)
		close(tdConn.readChannel)
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
			_, err = tdConn.read_msg(S2C_Transition_S2C_NO_CHANGE)
			if err != nil {
				if err.Error() == "MSG_CLOSE" {
					err = io.EOF
					return
				}
				Logger.Debugln("[Flow " + tdConn.idStr() + "] read err", err)
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
		runtime.Gosched()
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
			Logger.Debugf("[Flow " + tdConn.idStr() + "] connect fail", _err)
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

	var expectedTransition S2C_Transition
	var connection_attempts int

	// Randomize tdConn.maxSend to avoid heuristics
	tdConn.maxSend = uint64(getRandInt(sendLimitMin, sendLimitMax))

	if reconnect {
		connection_attempts = 2
		expectedTransition = S2C_Transition_S2C_CONFIRM_RECONNECT
		awaitFINTimeout := time.After(waitForFINTimeout * time.Second)
		readerStopped := false
		for !readerStopped {
			select {
			case _ = <-tdConn.readerStopped:
			// wait for readEngine to stop
				readerStopped = true
				continue
			case <-awaitFINTimeout:
				Logger.Errorf("[Flow " + tdConn.idStr() + "] FIN await timeout!")
				tdConn.tlsConn.Close()
			case <-tdConn.stopped:
				return
			}
		}
		tdConn.tlsConn.Close()
	} else {
		connection_attempts = 6
		expectedTransition = S2C_Transition_S2C_SESSION_INIT
	}

	for i := 0; i < connection_attempts; i++ {
		if !reconnect {
			// sleep to prevent overwhelming decoy servers
			if waitTime := sleepBeforeConnect(i); waitTime != nil {
				select {
				case <-waitTime:
				case <-tdConn.stopped:
					return
				}
			}
			tdConn.decoySNI, tdConn.decoyAddr = Assets().GetDecoyAddress()
		}

		currErr = tdConn.establishTLStoDecoy()
		if currErr != nil {
			Logger.Errorf("[Flow " + tdConn.idStr() + "] establishTLStoDecoy(" +
				tdConn.decoySNI + "," + tdConn.decoyAddr +
				") failed with " + currErr.Error())
			continue
		} else {
			Logger.Infof("[Flow " + tdConn.idStr() +
				"] Connected to decoy " + tdConn.decoySNI)
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
		if !cipherIsSupported(tdConn.tlsConn.ConnectionState().CipherSuite) {
			Logger.Errorf("[Flow " + tdConn.idStr() +
				"] decoy " + tdConn.decoySNI + ", offered unsupported cipher #" +
				strconv.FormatUint(uint64(tdConn.tlsConn.ConnectionState().CipherSuite), 10))
			currErr = errors.New("Unsupported cipher.")
			tdConn.tlsConn.Close()
			continue
		}

		tdConn.SetDeadline(time.Now().Add(deadlineConnectTDStation * time.Second))

		var tdRequest string
		tdRequest, currErr = tdConn.prepareTDRequest()
		Logger.Debugf("[Flow " + tdConn.idStr() +
			"] Prepared initial TD request:" + tdRequest)
		if currErr != nil {
			Logger.Errorf("[Flow " + tdConn.idStr() +
				"] Preparation of initial TD request failed with " + currErr.Error())
			tdConn.tlsConn.Close()
			continue
		}

		tdConn.sentTotal = 0
		_, currErr = tdConn.write_td([]byte(tdRequest), true)
		if currErr != nil {
			Logger.Errorf("[Flow " + tdConn.idStr() +
				"] Could not send initial TD request, error: " + currErr.Error())
			tdConn.tlsConn.Close()
			continue
		}

		_, currErr = tdConn.read_msg(expectedTransition)
		if currErr != nil {
			str_err := currErr.Error()
			if strings.Contains(str_err, ": i/o timeout") || // client timed out
				currErr.Error() == "EOF" {
				// decoy timed out
				currErr = errors.New("TapDance station didn't pick up the request: " + str_err)
				Logger.Errorf("[Flow " + tdConn.idStr() +
					"] " + currErr.Error())
			} else {
				// any other error will be fatal
				Logger.Errorf("[Flow " + tdConn.idStr() +
					"] fatal error reading from TapDance station: " +
					currErr.Error())
				tdConn.setError(currErr, false)
				return
			}
			tdConn.tlsConn.Close()
			continue
		}

		// TapDance should NOT have a timeout, timeouts have to be handled by client and server
		tdConn.SetDeadline(time.Time{}) // unsets timeout
		tdConn.writerTimeout = time.After(time.Duration(getRandInt(timeoutMin, timeoutMax)) *
			time.Second)
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
	// TODO: Doesn't support multiple readers

	// If there's no ready data in buffer - get some
	if tdConn.read_data_count == 0 {
		var open bool
		tdConn.read_data_buffer, open = <-tdConn.readChannel
		if open {
			tdConn.read_data_count = len(tdConn.read_data_buffer)
			tdConn.read_data_index = 0
		} else {
			return 0, tdConn.getError()
		}
	}

	// If there is unread data in buffer - copy it
	if tdConn.read_data_count > 0 {
		n = tdConn.read_data_count
		if n > cap(b) {
			n = cap(b)
		}
		n = copy(b, tdConn.read_data_buffer[tdConn.read_data_index:tdConn.read_data_index + n])
		b = b[:]
		tdConn.read_data_index += n
		tdConn.read_data_count -= n
	}
	if n == 0 {
		err = tdConn.getError()
	}
	return
}

func (tdConn *tapdanceConn) read_msg(expectedTransition S2C_Transition) (n int, err error) {
	// For each message we first read outer protocol header to see if it's protobuf or data

	var readBytes int
	var readBytesTotal uint32 // both header and body
	headerSize := uint32(2)
	totalBytesToRead := headerSize // first -- just header, then +body
	defer func() {
		n = int(readBytesTotal)
	}()

	var msgLen uint32 // just the body(e.g. raw data or protobuf)

	/*
	Each message is a 16-bit net-order int "TL" (type+len), followed by a data blob.
	If TL is negative, the blob is pure app data, with length abs(TL).
	If TL is positive, the blob is a protobuf, with length TL.
	If TL is 0, then read the following 4 bytes. Those 4 bytes are a net-order u32.
            This u32 is the length of the blob, which begins after this u32.
            The blob is a protobuf.
	*/
	const (
		msg_raw_data = iota
		msg_protobuf
	)
	var outerProtoMsgType uint8

	//TODO: check FIN+last data case
	for readBytesTotal < headerSize {
		readBytes, err = tdConn.tlsConn.Read(tdConn._readBuffer[readBytesTotal:headerSize])

		readBytesTotal += uint32(readBytes)
		if err == io.EOF && readBytesTotal == headerSize {
			break
		}
		if err != nil {
			return
		}
	}

	Uint16toInt16 := func(i uint16) int16 {
		// get your shit together, Golang
		u := int16(i >> 1)
		if i & 1 != 0 {
			u = ^u
		}
		return u
	}
	// Get TIL
	typeLen := Uint16toInt16(binary.BigEndian.Uint16(tdConn._readBuffer[0:2]))
	if typeLen < 0 {
		outerProtoMsgType = msg_raw_data
		msgLen = uint32(-typeLen)
	} else if typeLen > 0 {
		outerProtoMsgType = msg_protobuf
		msgLen = uint32(typeLen)
	} else {
		// protobuf with size over 32KB, not fitting into 2-byte TL
		outerProtoMsgType = msg_protobuf
		headerSize += 4
		for readBytesTotal < headerSize {
			readBytes, err = tdConn.tlsConn.Read(tdConn._readBuffer[readBytesTotal:headerSize])

			readBytesTotal += uint32(readBytes)
			if err == io.EOF && readBytesTotal == headerSize {
				break
			}
			if err != nil {
				return
			}
		}
		msgLen = binary.BigEndian.Uint32(tdConn._readBuffer[2:6])
	}
	Logger.Debugln("[Flow " + tdConn.idStr() + "] typeLen:", typeLen)
	Logger.Debugln("[Flow " + tdConn.idStr() + "] msgLen:", msgLen)

	totalBytesToRead = headerSize + msgLen
	read_buffer := make([]byte, msgLen)

	// Get the message itself
	for readBytesTotal < totalBytesToRead {
		readBytes, err = tdConn.tlsConn.Read(read_buffer[readBytesTotal - headerSize:msgLen])
		readBytesTotal += uint32(readBytes)
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
	}

	switch outerProtoMsgType {
	case msg_raw_data:
		n = int(readBytesTotal - headerSize)
			select {
			case tdConn.readChannel <- read_buffer[:]:
				Logger.Debugf("[Flow " + tdConn.idStr() +
					"] Successfully read DATA msg from server", msgLen)
			case <-tdConn.stopped:
				return
			}
	case msg_protobuf:
		msg := StationToClient{}
		err = proto.Unmarshal(read_buffer[:], &msg)
		if err != nil {
			return
		}

		// handle state transitions
		stateTransition := msg.GetStateTransition()
		if expectedTransition != S2C_Transition_S2C_NO_CHANGE {
			if expectedTransition != stateTransition {
				err = errors.New("State Transition mismatch! Expected: " +
					expectedTransition.String() +
					", but received: " + stateTransition.String())
				return
			}
		}
		switch stateTransition {
		case S2C_Transition_S2C_CONFIRM_RECONNECT:
			fallthrough
		case S2C_Transition_S2C_SESSION_INIT:
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
		case S2C_Transition_S2C_SESSION_CLOSE:
			err = errors.New("MSG_CLOSE")
			Logger.Infof("[Flow " + tdConn.idStr() +
				"] received MSG_CLOSE")
		}

		// handle ConfigInfo
		if confInfo := msg.GetConfigInfo(); confInfo != nil {
			// handle DecoyList
			// TODO: Debugln whole msg
			if decoysUpd := confInfo.GetDecoyList(); decoysUpd != nil {
				if decoysUpd.GetGeneration() >= Assets().getDecoyListGeneration() {
					Assets().SetDecoyList(decoysUpd.GetTlsDecoys())
					if pubKey := decoysUpd.GetDefaultPubkey(); pubKey != nil {
						switch pubKey.GetType() {
						case KeyType_AES_GCM_128:
							Assets().SetPubkey(pubKey.Key)
						default:
							// TODO: print error
						}
					}
				}
			}

			// handle some future config inside of ConfigInfo
		}

	default: panic("Corrupted outerProtoMsgType")
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
		tdConn.writeReconnects++
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

	n, err = tdConn.tlsConn.Write(b[:toSend])

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
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
	tls.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
	tls.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
	tls.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
}

func (tdConn *tapdanceConn) establishTLStoDecoy() (err error) {
	config := getZtlsConfig("Firefox50", tdConn.decoySNI)
	var dialConn net.Conn
	if tdConn.customDialer != nil {
		dialConn, err = tdConn.customDialer("tcp", tdConn.decoyAddr)
		if err != nil {
			return err
		}
	} else {
		dialConn, err = net.DialTimeout("tcp", tdConn.decoyAddr,
			deadlineTCPtoDecoy * time.Second)
		if err != nil {
			return err
		}
	}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(tdConn.decoyAddr)
		if err != nil {
			dialConn.Close()
			return
		}
		Logger.Infoln("[Flow " + tdConn.idStr() + "]: SNI was nil. Setting it to" +
			config.ServerName)
	}
	tdConn.tlsConn = tls.Client(dialConn, &config)
	err = tdConn.tlsConn.Handshake()
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

	if servConnCipher, ok := tdConn.tlsConn.OutCipher().(cipher.AEAD); ok {
		keystream = servConnCipher.Seal(nil, tdConn.tlsConn.OutSeq(), zeros, nil)
		return
	} else {
		err = errors.New("Could not convert tlsConn.OutCipher to cipher.AEAD")
	}
	return
}

func (tdConn *tapdanceConn) prepareTDRequest() (tdRequest string, err error) {
	// Generate initial TapDance request
	buf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES

	master_key := tdConn.tlsConn.GetHandshakeLog().KeyMaterial.MasterSecret.Value

	// write flags
	if err = binary.Write(buf, binary.BigEndian, uint8(0)); err != nil {
		return
	}
	buf.Write(master_key[:])
	buf.Write(tdConn.serverRandom())
	buf.Write(tdConn.clientRandom())
	buf.Write(tdConn.remoteConnId[:]) // connection id for persistence

	tag, err := obfuscateTag(buf.Bytes(), *tdConn.stationPubkey) // What we encode into the ciphertext
	if err != nil {
		return
	}

	// Don't even need the following HTTP request
	// Ideally, it is never processed by decoy
	tdRequest = "GET / HTTP/1.1\r\n"
	tdRequest += "Host: " + tdConn.decoySNI + "\r\n"
	tdRequest += "X-Ignore: "

	tdRequest += getRandPadding(0, 750, 10)

	keystreamOffset := len(tdRequest)
	keystreamSize := (len(tag) / 3 + 1) * 4 + keystreamOffset // we can't use first 2 bits of every byte
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

func (tdConn *tapdanceConn) clientRandom() []byte {
	return tdConn.tlsConn.GetHandshakeLog().ClientHello.Random
}

func (tdConn *tapdanceConn) serverRandom() []byte {
	return tdConn.tlsConn.GetHandshakeLog().ServerHello.Random
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (tdConn *tapdanceConn) Close() (err error) {
	tdConn.setError(errors.New("Forced shutdown by user"), false)
	tdConn.closeOnce.Do(func() {
		close(tdConn.stopped)
		atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
		if tdConn.tlsConn != nil {
			err = tdConn.tlsConn.Close()
		}
		return
	})
	return errors.New("Already closed")
}

// LocalAddr returns the local network address.
func (tdConn *tapdanceConn) LocalAddr() net.Addr {
	return tdConn.tlsConn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (tdConn *tapdanceConn) RemoteAddr() net.Addr {
	return tdConn.tlsConn.RemoteAddr()
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
	return tdConn.tlsConn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (tdConn *tapdanceConn) SetReadDeadline(t time.Time) error {
	return tdConn.tlsConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (tdConn *tapdanceConn) SetWriteDeadline(t time.Time) error {
	return tdConn.tlsConn.SetWriteDeadline(t)
}
