package tapdance

import (
	"crypto/rand"
	"errors"
	"net"
	"strconv"
)

/* Pluggable Transports 2.0 Specification, Draft 2 */
// The TransportConn interface represents a transport connection.
// The primary function of a transport connection is to provide the
// net.Conn interface.
// This interface also exposes access to an underlying network connection,
// which also implements net.Conn.
// TransportConn implements the Connection​ abstract interface.
type TransportConn interface {
	// The TransportConn interface extends net.Conn, the standard Go
	// interface for sockets.
	// This line means that a TransportConn has all of the same methods as a
	// normal Go socket.
	// The transport-specific logic for obfuscating network traffic is
	// implemented inside the methods inherited from net.Conn.
	net.Conn

	// Conn for the underlying network connection
	NetworkConn() net.Conn
}

type DualConn struct {
	net.Conn
	writerConn *tapdanceFlowConn
	readerConn *tapdanceFlowConn

	sessionId uint64 // constant for logging
}

// returns TapDance connection that utilizes 2 flows underneath: reader and writer
func dialSplitFlow(customDialer func(string, string) (net.Conn, error),
	id uint64) (net.Conn, error) {
	dualConn := DualConn{sessionId: id}
	stationPubkey := Assets().GetPubkey()

	remoteConnId := make([]byte, 16)
	rand.Read(remoteConnId[:])

	rawRConn := makeTdRaw(HTTP_GET_INCOMPLETE,
		stationPubkey[:],
		remoteConnId[:])
	rawRConn.customDialer = customDialer
	rawRConn.sessionId = id
	rawRConn.strIdSuffix = "R"

	err := rawRConn.Dial()
	if err != nil {
		return nil, err
	}
	dualConn.readerConn, err = makeTdFlow(FlowReadOnly, &rawRConn)
	if err != nil {
		return nil, err
	}

	// net.Conn functions that are not explicitly declared will be performed by readerConn
	dualConn.Conn = dualConn.readerConn

	// TODO: traffic fingerprinting issue
	// TODO: fundamental issue of observable dependency between 2 flows
	err = dualConn.readerConn.YieldUpload()
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		return nil, err
	}

	rawWConn := makeTdRaw(HTTP_POST_INCOMPLETE,
		stationPubkey[:],
		remoteConnId[:])
	rawWConn.customDialer = customDialer
	rawWConn.sessionId = id
	rawWConn.strIdSuffix = "W"
	rawWConn.decoySpec = rawRConn.decoySpec
	rawWConn.pinDecoySpec = true

	err = rawWConn.Dial()
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		return nil, err
	}
	dualConn.writerConn, err = makeTdFlow(FlowUpload, &rawWConn)
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		return nil, err
	}
	err = dualConn.writerConn.AcquireYield()
	if err != nil {
		dualConn.readerConn.closeWithErrorOnce(err)
		dualConn.writerConn.closeWithErrorOnce(err)
		return nil, err
	}
	/* // TODO: yield confirmation
	writerConn.yieldConfirmed = make(chan struct{})
	go func() {
		time.Sleep(time.Duration(getRandInt(1234, 5432)) * time.Millisecond)
		Logger().Infoln(dualConn.idStr() + " faking yield confirmation!")
		writerConn.yieldConfirmed <- struct{}{}
	}()
	err = writerConn.WaitForYieldConfirmation()
	if err != nil {
		dualConn.readerConn.Close()
		writerConn.Close()
		return nil, err
	}
	*/
	go func() {
		select {
		case <-dualConn.readerConn.closed:
			dualConn.writerConn.closeWithErrorOnce(errors.New("in paired readerConn: " +
				dualConn.readerConn.closeErr.Error()))
		case <-dualConn.writerConn.closed:
			dualConn.readerConn.closeWithErrorOnce(errors.New("in paired writerConn: " +
				dualConn.writerConn.closeErr.Error()))
		}
	}()
	return &dualConn, nil
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (tdConn *DualConn) Write(b []byte) (int, error) {
	return tdConn.writerConn.Write(b)
}

func (tdConn *DualConn) idStr() string {
	return "[Session " + strconv.FormatUint(tdConn.sessionId, 10) + "]"
}
