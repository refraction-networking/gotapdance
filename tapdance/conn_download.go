package tapdance

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/SergeyFrolov/bsbuffer"
	"github.com/golang/protobuf/proto"
	"io"
	"net"
	"sync"
	"time"
)

type tapdanceRConn struct {
	tdConn    *Conn
	tdRaw     *tdRawConn
	bsbuf     *bsbuffer.BSBuffer
	recvbuf   bytes.Buffer
	headerBuf [6]byte

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

/*
NOTE: DialRConn does NOT track amounts of uploaded data against upload limit, as it is currently
guaranteed to never exceed current min limit of 13kB.
Shall this ever change -- please take needed precautions and reconnect.
*/

// Establishes initial connection to TapDance station
// Doesn't yield upload and acts as read flow
func DialRConn(tdRaw tdRawConn, tdConn *Conn) (rConn *tapdanceRConn, err error) {
	if tdRaw.tlsConn == nil {
		// dial tdRawConn if not dialed yet
		err = tdRaw.Dial()
		if err != nil {
			return
		}
	}

	rConn = &tapdanceRConn{tdRaw: &tdRaw, tdConn: tdConn}

	// don't lose initial msg from station
	// strip off state transition and push protobuf up for processing
	rConn.tdRaw.initialMsg.StateTransition = nil
	err = rConn.tdConn.processProto(tdRaw.initialMsg)
	if err != nil {
		return
	}

	rConn.bsbuf = bsbuffer.NewBSBuffer()
	rConn.closed = make(chan struct{})
	rConn.updateReadDeadline()
	go rConn.spawnReaderEngine()
	return
}

func (rConn *tapdanceRConn) Read(b []byte) (int, error) {
	return rConn.bsbuf.Read(b)
}

func (rConn *tapdanceRConn) updateReadDeadline() {
	amortizationVal := 0.9
	const minSubtrahend = 50
	const maxSubtrahend = 9500
	deadline := rConn.tdRaw.establishedAt.Add(time.Millisecond *
		time.Duration(int(float64(rConn.tdRaw.decoySpec.GetTimeout())*amortizationVal)-
			getRandInt(minSubtrahend, maxSubtrahend)))
	rConn.tdRaw.tlsConn.SetReadDeadline(deadline)
}

func (rConn *tapdanceRConn) spawnReaderEngine() {
	defer rConn.bsbuf.Unblock()
	for {
		msgType, msgLen, err := rConn.readHeader()
		if err != nil {
			rConn.closeWithErrorOnce(err)
			return
		}
		if msgLen == 0 {
			continue // wtf?
		}
		switch msgType {
		case msg_raw_data:
			buf, err := rConn.readRawData(msgLen)
			if err != nil {
				rConn.closeWithErrorOnce(err)
				return
			}
			_, err = rConn.bsbuf.Write(buf)
			if err != nil {
				rConn.closeWithErrorOnce(err)
				return
			}
		case msg_protobuf:
			msg, err := rConn.readProtobuf(msgLen)
			if err != nil {
				rConn.closeWithErrorOnce(err)
				return
			}
			// push protobuf up for processing
			err = rConn.tdConn.processProto(msg)
			if err != nil {
				rConn.closeWithErrorOnce(err)
				return
			}
		default:
			rConn.closeWithErrorOnce(errors.New("Corrupted outer protocol header: " +
				msgType.Str()))
			return
		}
	}
}

// Action to take based on error
type ErrVerdict int32

const (
	ErrVerdictCarryOn           ErrVerdict = 0
	ErrVerdictScheduleReconnect ErrVerdict = 1
	ErrVerdictStartReconnect    ErrVerdict = 2
	ErrVerdictClose             ErrVerdict = 3
	ErrVerdictCrash             ErrVerdict = 4
)

func (rConn *tapdanceRConn) readRawData(msgLen int) (buf []byte, err error) {
	rConn.recvbuf.Reset()
	rConn.recvbuf.Grow(msgLen)
	var readBytes int64
	var readBytesTotal int // both header and body
	// Get the message itself
	for readBytesTotal < msgLen {
		readBytes, err = rConn.recvbuf.ReadFrom(rConn.tdRaw.tlsConn) // TODO: is it blocking?
		readBytesTotal += int(readBytes)
		buf = rConn.recvbuf.Bytes()
		if err != nil {
			err = rConn.actOnReadError(err)
			if err != nil {
				return
			}
		}
	}
	return
}

func (rConn *tapdanceRConn) readProtobuf(msgLen int) (msg StationToClient, err error) {
	rbuf := make([]byte, msgLen)
	var readBytes int
	var readBytesTotal int // both header and body
	// Get the message itself
	for readBytesTotal < msgLen {
		readBytes, err = rConn.tdRaw.tlsConn.Read(rbuf[readBytesTotal:])
		readBytesTotal += readBytes
		if err != nil {
			err = rConn.actOnReadError(err)
			if err != nil {
				return
			}
		}
	}
	err = proto.Unmarshal(rbuf[:], &msg)
	return
}

func (rConn *tapdanceRConn) readHeader() (msgType MsgType, msgLen int, err error) {
	// For each message we first read outer protocol header to see if it's protobuf or data

	var readBytes int
	var readBytesTotal uint32 // both header and body
	headerSize := uint32(2)

	//TODO: check FIN+last data case
	for readBytesTotal < headerSize {
		readBytes, err = rConn.tdRaw.tlsConn.Read(rConn.headerBuf[readBytesTotal:headerSize])
		readBytesTotal += uint32(readBytes)
		if err != nil {
			err = rConn.actOnReadError(err)
			if err != nil {
				return
			}
		}
	}

	// Get TIL
	typeLen := Uint16toInt16(binary.BigEndian.Uint16(rConn.headerBuf[0:2]))
	if typeLen < 0 {
		msgType = msg_raw_data
		msgLen = int(-typeLen)
	} else if typeLen > 0 {
		msgType = msg_protobuf
		msgLen = int(typeLen)
	} else {
		// protobuf with size over 32KB, not fitting into 2-byte TL
		msgType = msg_protobuf
		headerSize += 4
		for readBytesTotal < headerSize {
			readBytes, err = rConn.tdRaw.tlsConn.Read(rConn.headerBuf[readBytesTotal:headerSize])
			readBytesTotal += uint32(readBytes)
			if err != nil {
				err = rConn.actOnReadError(err)
				if err != nil {
					return
				}
			}
		}
		msgLen = int(binary.BigEndian.Uint32(rConn.headerBuf[2:6]))
	}
	return
}

// Allows scheduling/doing reconnects in the middle of reads
func (rConn *tapdanceRConn) actOnReadError(readErr error) (err error) {
	switch rConn.getErrorVerdict(readErr) {
	case ErrVerdictCarryOn:
		return
	case ErrVerdictScheduleReconnect:
		rConn.tdRaw.tlsConn.SetReadDeadline(
			time.Now().Add(time.Millisecond * time.Duration(getRandInt(7777, 9999))))
		_, err = rConn.tdRaw.writeTransition(C2S_Transition_C2S_EXPECT_RECONNECT)
		if err != nil {
			return
		}
		err = rConn.tdRaw.closeWrite()
		if err != nil {
			// do it rough?
			rConn.tdRaw.Close()
		}
	case ErrVerdictStartReconnect:
		err = rConn.tdRaw.Redial()
		if err != nil {
			return
		}
		// strip off state transition and push protobuf up for processing
		rConn.tdRaw.initialMsg.StateTransition = nil
		err = rConn.tdConn.processProto(rConn.tdRaw.initialMsg)
		if err != nil {
			return
		}
		rConn.updateReadDeadline()
	case ErrVerdictClose:
		err = io.EOF
	case ErrVerdictCrash:
		err = io.ErrUnexpectedEOF
	}
	return
}

func (rConn *tapdanceRConn) getErrorVerdict(err error) ErrVerdict {
	if err == nil {
		return ErrVerdictCarryOn
	}
	if err == errMsgClose {
		// errMsgClose actually won't show up here
		Logger().Infoln(rConn.tdRaw.idStr() + " got MSG_CLOSE")
		return ErrVerdictClose
	}
	if err, ok := err.(net.Error); ok && err.Timeout() {
		Logger().Infoln(rConn.tdRaw.idStr() + " scheduling reconnect due to " + err.Error())
		return ErrVerdictScheduleReconnect
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		Logger().Infoln(rConn.tdRaw.idStr() + " starting reconnect due to " + err.Error())
		return ErrVerdictStartReconnect
	}
	if nErr, ok := err.(*net.OpError); ok {
		Logger().Infoln(rConn.tdRaw.idStr() + " starting reconnect due to " + err.Error())
		if nErr.Err.Error() == "use of closed network connection" {
			return ErrVerdictStartReconnect
		}
	}
	Logger().Infoln(rConn.tdRaw.idStr() + " crash ErrorVerdict due to " + err.Error())
	return ErrVerdictCrash
}

func (rConn *tapdanceRConn) YieldUpload() error {
	_, err := rConn.tdRaw.writeTransition(C2S_Transition_C2S_YIELD_UPLOAD)
	if err != nil {
		Logger().Infoln(rConn.idStr() + " Failed attempt to yield upload:" + err.Error())
	} else {
		Logger().Infoln(rConn.idStr() + " Sent yield upload request")
	}
	return err
}

// Closes connection, channel and sets error ONCE, e.g. error won't be overwritten
func (rConn *tapdanceRConn) closeWithErrorOnce(err error) {
	if err != nil {
		// safeguard, shouldn't happen
		err = errors.New("closed with nil error!")
	}
	rConn.closeOnce.Do(func() {
		rConn.bsbuf.Unblock()
		rConn.closeErr = errors.New(rConn.idStr() + " " + err.Error())
		close(rConn.closed)
		rConn.tdRaw.Close()
	})
}

func (rConn *tapdanceRConn) Close() error {
	rConn.closeWithErrorOnce(errors.New("closed externally"))
	return rConn.closeErr
}

func (rConn *tapdanceRConn) idStr() string {
	return rConn.tdRaw.idStr()
}
