// +build ignore

package tapdance

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/zmap/zcrypto/tls"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"fmt"
)

type tapdanceRWConn struct {
	tcpConn      *net.TCPConn
	tlsConn      *tls.Conn
	customDialer func(string, string) (net.Conn, error)

	sessionId uint64 // for logging. Constant for tapdanceConn
	flowId    int    // for logging. Increments with each attempt to reconnect
	/* random per-connection (secret) id;
	   this way, the underlying SSL connection can disconnect
	   while the client's local conn and station's proxy conn
	   can stay connected */
	remoteConnId [16]byte

	maxSend   int
	sentTotal int

	decoyAddr string // ipv4_addr:port
	decoySNI  string

	_readBuffer  []byte
	_writeBuffer []byte

	writeMsgSize  int
	writeMsgIndex int
	writeBufType  MsgType // appdata or protobug

	stationPubkey *[32]byte

	state int32
	err   error      // closing error
	errMu sync.Mutex // make it RWMutex and RLock on read?

	readChannel  chan []byte // HAVE TO BE NON-BLOCKING
	writeChannel chan []byte //

	statsUpload   chan int
	statsDownload chan int

	readerTimeout <-chan time.Time
	writerTimeout <-chan time.Time

	// used by 2 engines to communicate /w one another
	// true is sent upon success
	readerStopped chan bool
	writerStopped chan bool
	doneReconnect chan bool
	stopped       chan bool
	closeOnce     sync.Once

	// read_data holds data between Read() calls when the
	// caller's buffer is to small to receive all the data
	// read in a message from the station.
	read_data_buffer []byte
	read_data_index  int
	read_data_count  int

	receive_buffer     []byte
	receive_buffer_idx int

	// for statistics
	writeReconnects   int
	timeoutReconnects int

	transitionMsg ClientToStation

	failedDecoys []string
}

/* Create new TapDance connection
Args:
	id            -- only for logging and TapDance proxy, could be ignored
	customDialer  -- dial with customDialer, could be nil
*/
func dialRWTapDance(
	id uint64,
	customDialer func(string, string) (net.Conn, error)) (tdConn *tapdanceRWConn, err error) {

	tdConn = new(tapdanceRWConn)

	tdConn.customDialer = customDialer
	tdConn.sessionId = id
	tdConn.flowId = -1
	tdConn.tlsConn = nil

	tdConn.stationPubkey = Assets().GetPubkey()

	rand.Read(tdConn.remoteConnId[:])

	tdConn._readBuffer = make([]byte, 6) // Only read headers into it
	tdConn._writeBuffer = make([]byte, 16*1024+20+20+12)

	tdConn.stopped = make(chan bool)
	tdConn.readerStopped = make(chan bool)
	tdConn.writerStopped = make(chan bool)
	tdConn.doneReconnect = make(chan bool)
	tdConn.writeChannel = make(chan []byte)
	tdConn.readChannel = make(chan []byte, 1)

	tdConn.statsUpload = make(chan int, 32)
	tdConn.statsDownload = make(chan int, 32)

	tdConn.state = TD_STATE_NEW
	//tdConn.connect()

	err = tdConn.err
	if err == nil {
		/* If connection was successful, TapDance launches 3 goroutines:
		first one handles sending of the data and does reconnection,
		second goroutine handles reading, last one prints bandwidth stats.
		*/
		go tdConn.readSubEngine()
		go tdConn.engineMain()
		go tdConn.loopPrintBandwidth()
	}
	return
}

// Does writing to socket and reconnection
func (tdConn *tapdanceRWConn) engineMain() {
	defer func() {
		Logger.Debugln(tdConn.idStr() + " exit engineMain()")
		close(tdConn.doneReconnect)
		close(tdConn.writerStopped)
		tdConn.Close()
	}()

	for {
		switch atomic.LoadInt32(&tdConn.state) {
		case TD_STATE_RECONNECT:
			err := tdConn.writeTransition(C2S_Transition_C2S_EXPECT_RECONNECT)
			if err != nil {
				Logger.Infoln(tdConn.idStr() + " writeTransition(RECONNECT) " +
					"failed with " + err.Error())
				tdConn.setError(err, false)
				return
			}
			tdConn.tcpConn.CloseWrite()
			Logger.Debugln(tdConn.idStr() + " write closed")
			Logger.Infoln(tdConn.idStr() + " reconnecting!" +
				" write_total: " + strconv.Itoa(tdConn.writeReconnects) +
				" timeout_total: " + strconv.Itoa(tdConn.timeoutReconnects))
			//tdConn.connect()
			continue
		case TD_STATE_CONNECTED:
		default:
			return
		}

		// If just reconnected, but still have user outgoing user data - send it
		if tdConn.writeMsgSize != 0 {
			_, err := tdConn.writeBufferedData()
			if err != nil {
				Logger.Infoln(tdConn.idStr() + " re writeRaw() " +
					"failed with " + err.Error())
				tdConn.setError(err, false)
				return
			}
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
			tdConn.writeBufType = msg_raw_data
			_, err := tdConn.writeBufferedData()
			if err != nil {
				Logger.Infoln(tdConn.idStr() + " writeRaw() " +
					"failed with " + err.Error())
				tdConn.setError(err, false)
				return
			}
		}
	}
}

// Reads from socket, sleeps during reconnection
func (tdConn *tapdanceRWConn) readSubEngine() {
	var err error
	defer func() {
		tdConn.setError(err, false)
		Logger.Debugln(tdConn.idStr() + " exit readSubEngine()")
		tdConn.Close()
		close(tdConn.readerStopped)
		if tdConn.receive_buffer_idx != 0 {
			tdConn.readChannel <- tdConn.receive_buffer[:tdConn.receive_buffer_idx]
		}
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
			}
		default:
			return
		}

		if tdConn.receive_buffer_idx != 0 {
			select {
			case tdConn.readChannel <- tdConn.receive_buffer[:tdConn.receive_buffer_idx]:
				tdConn.receive_buffer_idx = 0
				tdConn.receive_buffer = make([]byte, 0)
			default:
			}
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
				Logger.Debugln(tdConn.idStr()+" read err", err)
				toReconnect = (err == io.EOF || err == io.ErrUnexpectedEOF)
				if nErr, ok := err.(*net.OpError); ok {
					if nErr.Err.Error() == "use of closed network connection" {
						toReconnect = true
					}
				}

				if toReconnect {
					continue
				} else {
					Logger.Infoln(tdConn.idStr() + " read_msg() " +
						"failed with " + err.Error())
					return
				}
			}
		}
		runtime.Gosched()
	}
}

// Read reads data from the connection.
// TODO: Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
// TODO: Ideally should support multiple readers
func (tdConn *tapdanceRWConn) Read(b []byte) (n int, err error) {
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
		n = copy(b, tdConn.read_data_buffer[tdConn.read_data_index:tdConn.read_data_index+n])
		b = b[:]
		tdConn.read_data_index += n
		tdConn.read_data_count -= n
	}
	if n == 0 {
		err = tdConn.getError()
	}
	return
}

func (tdConn *tapdanceRWConn) read_msg(expectedTransition S2C_Transition) (n int, err error) {
	// For each message we first read outer protocol header to see if it's protobuf or data

	var readBytes int
	var readBytesTotal uint32 // both header and body
	headerSize := uint32(2)
	totalBytesToRead := headerSize // first -- just header, then +body
	defer func() {
		n = int(readBytesTotal)
		tdConn.statsDownload <- n
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
	var outerProtoMsgType MsgType

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

	totalBytesToRead = headerSize + msgLen
	read_buffer := make([]byte, msgLen)

	// Get the message itself
	for readBytesTotal < totalBytesToRead {
		readBytes, err = tdConn.tlsConn.Read(read_buffer[readBytesTotal-headerSize : msgLen])
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
		tdConn.receive_buffer = append(tdConn.receive_buffer[:],
			read_buffer...)
		n = int(msgLen)
		tdConn.receive_buffer_idx += n
	case msg_protobuf:
		msg := StationToClient{}
		err = proto.Unmarshal(read_buffer[:], &msg)
		if err != nil {
			return
		}
		Logger.Debugln(tdConn.idStr() + " received protobuf: " +
			msg.String())

	default:
		panic("Corrupted outerProtoMsgType")
	}
	return
}

// Write writes data to the connection.
// TODO: Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
// TODO: Ideally should support multiple readers
func (tdConn *tapdanceRWConn) Write(b []byte) (sentTotal int, err error) {
	if len(b) == 0 {
		return 0, tdConn.getError()
	}

	bb := make([]byte, len(b))
	copy(bb, b)
	select {
	case tdConn.writeChannel <- bb:
		sentTotal = len(bb)
	case <-tdConn.stopped:
	}
	if sentTotal == 0 {
		err = tdConn.getError()
	}
	return
}

func (tdConn *tapdanceRWConn) writeBufferedData() (n int, err error) {
	couldSend := tdConn.maxSend - tdConn.sentTotal
	totalToSendLeft := tdConn.writeMsgSize - tdConn.writeMsgIndex
	toSend := totalToSendLeft
	var b []byte

	Logger.Debugf(tdConn.idStr() +
		" Already sent: " + strconv.Itoa(tdConn.sentTotal) +
		". Requested to send: " + strconv.Itoa(totalToSendLeft))
	defer func() {
		tdConn.statsUpload <- n
	}()

	switch tdConn.writeBufType {
	case msg_protobuf:
		b = getMsgWithHeader(msg_protobuf, tdConn._writeBuffer[:tdConn.writeMsgSize])
		if len(b) > couldSend {
			Logger.Errorln("Could not send protobuf due to upload limit!")
			return 0, io.ErrShortWrite
		}
	case msg_raw_data:
		headerSize := 2
		maxChunkSize := getRandInt(32767, 32767)
		if couldSend > maxChunkSize {
			couldSend = maxChunkSize
		}
		/*
			/ Check if we are able to send the whole buffer or not(due to upload limit).
			/ We may want to split buffer into 2 or more chunks and send them chunk by chunk
			/ after reconnect(s). Unfortunately, we can't just always split it, as some
			/ protocols don't allow fragmentation, e.g. ssh will break, if you fragment pkts.
			/ And we don't really know which application is using TapDance: ssh-style or
			/ Extra-Jumbo-Frame-Over-16kB-style.
			/ That's why we will only fragment, if 0 bytes were sent in this connection, but
			/ data still doesn't fit. This way we will accommodate all.
		*/
		needReconnect := (couldSend < totalToSendLeft+headerSize)
		if needReconnect {
			tdConn.writeReconnects++
			tdConn.tryScheduleReconnect()
			if tdConn.sentTotal != 0 {
				// reconnect right away
				Logger.Infof(tdConn.idStr() + " triggered preemptive reconnect in Write()")
				return
			} else {
				// split buffer in chunks and reconnect after
				toSend = couldSend - headerSize
			}
		}
		// Temporary workaround for panic observed in production
        	if tdConn.writeMsgIndex >= len(tdConn._writeBuffer) || tdConn.writeMsgIndex+toSend > len(tdConn._writeBuffer) {
            		errMsg := fmt.Sprintf("tdConn._writeBuffer slice bounds out of range: %d[%d:%d] (%d, %d)",
                		len(tdConn._writeBuffer),
                		tdConn.writeMsgIndex,
                		tdConn.writeMsgIndex+toSend,
                		couldSend,
                		totalToSendLeft)
            		Logger.Infoln(tdConn.idStr() + " " + errMsg)
            		return 0, errors.New(errMsg)
        	}
		b = getMsgWithHeader(msg_raw_data,
			tdConn._writeBuffer[tdConn.writeMsgIndex:tdConn.writeMsgIndex+toSend])
	default:
		panic("writeBufferedData() writeBufType: " + strconv.Itoa(int(tdConn.writeBufType)))
	}

	n, err = tdConn.tlsConn.Write(b[:])
	tdConn.writeMsgIndex += toSend
	tdConn.sentTotal += n
	if tdConn.writeMsgIndex >= tdConn.writeMsgSize {
		tdConn.writeMsgIndex = 0
		tdConn.writeMsgSize = 0
	}
	return
}

// generates transition msg, which is sent before reconnects
// msg is saved to tdConn.transitionMsg
// returns size of serialized tdConn.transitionMsg
func (tdConn *tapdanceRWConn) preGenenerateTransition() int {
	dummyGen := uint32(0)
	dummyTransition := C2S_Transition_C2S_NO_CHANGE
	tdConn.transitionMsg = ClientToStation{StateTransition: &dummyTransition,
		DecoyListGeneration: &dummyGen,
		Padding:             []byte(getRandPadding(150, 950, 10))}
	return proto.Size(&tdConn.transitionMsg)
}

func (tdConn *tapdanceRWConn) writeListFailedDecoys() (err error) {
	currGen := Assets().GetGeneration()
	msgFailedDecoys := ClientToStation{DecoyListGeneration: &currGen,
		Padding:      []byte(getRandPadding(150, 500, 10)),
		FailedDecoys: tdConn.failedDecoys,
	}
	err = tdConn.writeProto(msgFailedDecoys)
	return
}

func (tdConn *tapdanceRWConn) writeTransition(transition C2S_Transition) (err error) {
	currGen := Assets().GetGeneration()
	tdConn.transitionMsg.DecoyListGeneration = &currGen
	tdConn.transitionMsg.StateTransition = &transition
	Logger.Debugln("tdConn.maxSend", tdConn.maxSend)
	tdConn.maxSend += (proto.Size(&tdConn.transitionMsg) + 2) // 2 bytes for header
	Logger.Debugln("tdConn.maxSend", tdConn.maxSend)

	err = tdConn.writeProto(tdConn.transitionMsg)
	return
}

/*
	Each message is a 16-bit net-order int "TL" (type+len), followed by a data blob.
	If TL is negative, the blob is pure app data, with length abs(TL).
	If TL is positive, the blob is a protobuf, with length TL.
	If TL is 0, then read the following 4 bytes. Those 4 bytes are a net-order u32.
	    This u32 is the length of the blob, which begins after this u32.
	    The blob is a protobuf.
*/

func (tdConn *tapdanceRWConn) writeProto(msg ClientToStation) error {
	msgBytes, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}

	// don't ever chunk protobufs
	couldSend := tdConn.maxSend - tdConn.sentTotal
	if couldSend < len(msgBytes) {
		// if we can't send it due to upload limit:
		//    buffer it, reconnect, and try again
		tdConn._writeBuffer = msgBytes
		tdConn.writeMsgSize = len(msgBytes)
		tdConn.writeMsgIndex = 0
		tdConn.writeBufType = msg_protobuf
		tdConn.writeReconnects++
		tdConn.tryScheduleReconnect()
		// reconnect right away
		Logger.Infoln(tdConn.idStr() + " triggered reconnect in writeProto()")
		Logger.Infoln(tdConn.idStr()+" protobuf was: ", msg.String())
		// switch ^ to Debugln when/if non-StateTransition protobufs are sent regularly
		return nil
	} else {
		Logger.Debugln(tdConn.idStr()+" sending protobuf: ", msg.String())
		// if upload doesn't prevent us from sending it - just do it
		// note that we always can send StateTransition, as space was reserved for it
		b := getMsgWithHeader(msg_protobuf, msgBytes)
		_, err = tdConn.tlsConn.Write(b)
		tdConn.sentTotal += len(b)
	}
	return err
}

func (tdConn *tapdanceRWConn) idStr() string {
	return "[Session " + strconv.FormatUint(uint64(tdConn.sessionId), 10) + ", " +
		"Flow " + strconv.Itoa(tdConn.flowId) + "]"
}

func (tdConn *tapdanceRWConn) setError(err error, overwrite bool) {
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

func (tdConn *tapdanceRWConn) getError() (err error) {
	tdConn.errMu.Lock()
	defer tdConn.errMu.Unlock()
	return tdConn.err
}

func (tdConn *tapdanceRWConn) loopPrintBandwidth() {
	getPrettyBandwidth := func(nBytes int) string {
		var power, remainder int
		for nBytes > 1024 {
			remainder = (nBytes % 1024) * 10 / 1024 // single digit after dot
			nBytes = nBytes / 1024
			power += 1
		}
		str := strconv.Itoa(nBytes) + "." + strconv.Itoa(remainder) + " "
		switch power {
		case 0:
			str += "B/s"
		case 1:
			str += "KB/s"
		case 2:
			str += "MB/s"
		case 3:
			str += "GB/s"
		case 4:
			str += "TB/s"
		default:
			panic("Unreliastic bandwidth")
		}
		return str
	}

	var totalBytesRead, bytesRead, totalBytesWritten, bytesWritten int
	var printTimeout <-chan time.Time
	for {
		if totalBytesWritten == 0 && totalBytesRead == 0 {
			printTimeout = time.After(1 * time.Second)
		}
		// TODO: it's imprecise, but totally good enough
		select {
		case bytesRead = <-tdConn.statsDownload:
			totalBytesRead += bytesRead
		case bytesWritten = <-tdConn.statsUpload:
			totalBytesWritten += bytesWritten
		case <-printTimeout:
			Logger.Infoln(tdConn.idStr() +
				" download: " + getPrettyBandwidth(totalBytesRead) +
				", upload: " + getPrettyBandwidth(totalBytesWritten))
			totalBytesWritten = 0
			totalBytesRead = 0
		case <-tdConn.stopped:
			return
		}
	}
}

func (tdConn *tapdanceRWConn) tryScheduleReconnect() {
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

func (tdConn *tapdanceRWConn) IsClosed() bool {
	select {
	case <-tdConn.stopped:
		return true
	default:
	}
	return false
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (tdConn *tapdanceRWConn) Close() (err error) {
	tdConn.setError(errors.New("Forced shutdown by user"), false)
	tdConn.closeOnce.Do(func() {
		close(tdConn.stopped)
		atomic.StoreInt32(&tdConn.state, TD_STATE_CLOSED)
		waitForWriterToDie := time.After(2 * time.Second)
		// TODO: stop sending SESSION_CLOSE if tdConn.tlsConn is closed
		// but there is no check =(
		select {
		case _ = <-tdConn.writerStopped:
			tdConn.writeTransition(C2S_Transition_C2S_SESSION_CLOSE)
			Logger.Infoln(tdConn.idStr() + " sent SESSION_CLOSE")
		case <-waitForWriterToDie:
			Logger.Infoln(tdConn.idStr() + " timed out. Not sending SESSION_CLOSE")
		}
		if tdConn.tlsConn != nil {
			err = tdConn.tlsConn.Close()
		}
		return
	})
	return errors.New("Already closed")
}

// LocalAddr returns the local network address.
func (tdConn *tapdanceRWConn) LocalAddr() net.Addr {
	return tdConn.tlsConn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (tdConn *tapdanceRWConn) RemoteAddr() net.Addr {
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
func (tdConn *tapdanceRWConn) SetDeadline(t time.Time) error {
	return tdConn.tlsConn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (tdConn *tapdanceRWConn) SetReadDeadline(t time.Time) error {
	return tdConn.tlsConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (tdConn *tapdanceRWConn) SetWriteDeadline(t time.Time) error {
	return tdConn.tlsConn.SetWriteDeadline(t)
}
