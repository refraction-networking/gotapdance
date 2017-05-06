package tapdance

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

type Conn struct {
	writerConn *tapdanceWConn
	readerConn *tapdanceRConn

	customDialer func(string, string) (net.Conn, error)

	remoteConnId  []byte
	stationPubkey *[32]byte

	sessionId uint64 // for logging. Constant for tapdanceConn

	headerBuffer []byte
}

// returns TapDance connection that utilizes 2 flows underneath: reader and writer
func doDialTDConn(customDialer func(string, string) (net.Conn, error), id uint64) (*Conn, error) {
	tdConn := new(Conn)
	tdConn.sessionId = id
	tdConn.customDialer = customDialer

	tdConn.stationPubkey = Assets().GetPubkey()

	tdConn.remoteConnId = make([]byte, 16)
	rand.Read(tdConn.remoteConnId[:])

	initialRawRConn := makeTdRaw(HTTP_GET_INCOMPLETE,
		tdConn.stationPubkey[:],
		tdConn.remoteConnId[:])
	initialRawRConn.strIdSuffix = "R"
	initialRawRConn.customDialer = tdConn.customDialer
	initialRawRConn.sessionId = tdConn.sessionId

	err := initialRawRConn.Dial()
	if err != nil {
		return nil, err
	}
	tdConn.readerConn, err = DialRConn(initialRawRConn, tdConn)
	if err != nil {
		return nil, err
	}

	err = tdConn.readerConn.YieldUpload()
	// TODO: traffic fingerprinting issue
	// TODO: fundamental issue of observable dependency between 2 flows
	if err != nil {
		tdConn.readerConn.Close()
		return nil, err
	}

	initialRawWConn := makeTdRaw(HTTP_POST_COMPLETE,
		tdConn.stationPubkey[:],
		tdConn.remoteConnId[:])
	initialRawWConn.strIdSuffix = "W"
	initialRawWConn.customDialer = tdConn.customDialer
	initialRawWConn.sessionId = tdConn.sessionId
	initialRawWConn.decoySpec = initialRawRConn.decoySpec
	initialRawWConn.pinDecoySpec = true

	err = initialRawWConn.Dial()
	if err != nil {
		tdConn.readerConn.Close()
		return nil, err
	}
	tdConn.writerConn, err = DialWConn(initialRawWConn, tdConn)
	if err != nil {
		tdConn.readerConn.Close()
		return nil, err
	}
	err = tdConn.writerConn.AcquireYield()
	if err != nil {
		tdConn.readerConn.Close()
		return nil, err
	}
	go func() {
		// TODO: actually do yield confirmation
		time.Sleep(time.Duration(getRandInt(1, 5432)) * time.Millisecond)
		Logger().Infoln(tdConn.idStr() + " faking yield confirmation!")
		tdConn.writerConn.yieldConfirmed <- struct{}{}
	}()
	err = tdConn.writerConn.WaitForYieldConfirmation()
	if err != nil {
		tdConn.readerConn.Close()
		return nil, err
	}
	return tdConn, nil
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (tdConn *Conn) Read(b []byte) (int, error) {
	return tdConn.readerConn.Read(b)
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (tdConn *Conn) Write(b []byte) (int, error) {
	return tdConn.writerConn.Write(b)
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (tdConn *Conn) Close() (err error) {
	if tdConn.writerConn != nil {
		err = tdConn.writerConn.Close()
	}
	if tdConn.readerConn != nil {
		err = tdConn.readerConn.Close()
	}
	return
}

func (tdConn *Conn) processProto(msg StationToClient) error {
	handleConfigInfo := func(conf *ClientConf) {
		currGen := Assets().GetGeneration()
		if conf.GetGeneration() < currGen {
			Logger().Infoln(tdConn.idStr()+" not appliying new config due"+
				" to lower generation: ", conf.GetGeneration(), " "+
				"(have:", currGen, ")")
			return
		} else if conf.GetGeneration() < currGen {
			Logger().Infoln(tdConn.idStr()+" not appliying new config due"+
				" to currently having same generation: ", currGen)
			return
		}

		_err := Assets().SetClientConf(conf)
		if _err != nil {
			Logger().Errorln(tdConn.idStr() +
				"Could not save SetClientConf():" + _err.Error())
		}
	}
	Logger().Infoln(tdConn.idStr() + " received protobuf: " + msg.String())
	// handle ConfigInfo
	if confInfo := msg.ConfigInfo; confInfo != nil {
		handleConfigInfo(confInfo)
		// TODO: if we ever get a ``safe'' decoy rotation - code below has to be rewritten
		if !Assets().IsDecoyInList(tdConn.readerConn.tdRaw.decoySpec) {
			Logger().Warningln(tdConn.idStr() + ": current decoy is no " +
				"longer in the list, changing it! Read flow probably will break!")
			// if current decoy is no longer in the list
			tdConn.readerConn.tdRaw.decoySpec = Assets().GetDecoy()
		}
		if !Assets().IsDecoyInList(tdConn.writerConn.tdRaw.decoySpec) {
			Logger().Warningln(tdConn.idStr() + " current decoy is no " +
				"longer in the list, changing it! Write flow probably will break!")
			// if current decoy is no longer in the list
			tdConn.writerConn.tdRaw.decoySpec = Assets().GetDecoy()
		}
	}
	stateTransition := msg.GetStateTransition()
	switch stateTransition {
	case S2C_Transition_S2C_NO_CHANGE:
	// carry on
	case S2C_Transition_S2C_SESSION_CLOSE:
		Logger().Infof(tdConn.idStr() + " received MSG_CLOSE")
		return errMsgClose
	case S2C_Transition_S2C_CONFIRM_RECONNECT:
		fallthrough
	case S2C_Transition_S2C_SESSION_INIT:
		fallthrough
	case S2C_Transition_S2C_ERROR:
		err := errors.New("received error message from station:" +
			msg.GetErrReason().String())
		Logger().Errorln(tdConn.idStr() + " " + err.Error())
		tdConn.Close()
		return err
	default:
		err := errors.New("Corrupted and Unexpected State Transition " +
			"in initialized Conn:" + stateTransition.String())
		Logger().Errorln(tdConn.idStr() + " " + err.Error())
		tdConn.Close()
		return err
	}
	return nil
}

// LocalAddr returns the local network address.
func (tdConn *Conn) LocalAddr() net.Addr {
	defer func() {
		if err := recover(); err != nil {
			Logger().Errorf("%s LocalAddr() panic recovery: %v\n", tdConn.idStr(), err)
			return
		}
	}()
	// not sure if this function is meaningful in TapDance context
	return tdConn.readerConn.tdRaw.tlsConn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (tdConn *Conn) RemoteAddr() net.Addr {
	defer func() {
		if err := recover(); err != nil {
			Logger().Errorf("%s RemoteAddr() panic recovery: %v\n", tdConn.idStr(), err)
			return
		}
	}()
	return tdConn.readerConn.tdRaw.tlsConn.RemoteAddr()
}

func (tdConn *Conn) idStr() string {
	return "[Session " + strconv.FormatUint(tdConn.sessionId, 10) + "]"
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (tdConn *Conn) SetDeadline(t time.Time) error {
	return errors.New("Not implemented") // TODO
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (tdConn *Conn) SetReadDeadline(t time.Time) error {
	return errors.New("Not implemented") // TODO
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (tdConn *Conn) SetWriteDeadline(t time.Time) error {
	return errors.New("Not implemented") // TODO
}
