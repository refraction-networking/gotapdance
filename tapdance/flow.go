package tapdance

import (
	"net"
	"strconv"
	"time"
	"io"
	"errors"
	"strings"
)

const (
	MSG_DATA = iota // iota auto increments
	MSG_INIT
	MSG_RECONNECT
	MSG_CLOSE
)

// Connection-oriented state
type TapDanceFlow struct {
	// tunnel index and start time
	id           uint
	startMs      uint64 // TODO: unused

	// reference to global proxy
	proxy        *TapdanceProxy

	servConn     *tapdanceConn
	userConn     net.Conn
};

// constructor
func NewTapDanceFlow(proxy *TapdanceProxy, id uint) *TapDanceFlow {
	state := new(TapDanceFlow)

	state.proxy = proxy
	state.id = id

	state.startMs = uint64(timeMs())

	Logger.Debugf("Created new TDState ", state)
	return state
}

func (TDstate *TapDanceFlow) Redirect() (err error) {
	TDstate.servConn, err = DialTapDance(TDstate.id, nil)
	if err != nil {
		TDstate.userConn.Close()
		return
	}
	errChan := make(chan error)
	defer TDstate.userConn.Close()
	defer TDstate.servConn.Close()

	forwardFromServerToClient := func ()() {
		b := make([]byte, 16 * 1024 + 20 + 20 + 12)
		for !TDstate.proxy.stop {
			n, err := TDstate.servConn.Read(b)
			if err != nil {
				errChan <- err
				return
			}
			if n > 0 {
				TDstate.userConn.SetWriteDeadline(time.Now().Add(time.Second * 2))
				sent_n, err := TDstate.userConn.Write(b[:n])
				if err != nil {
					errChan <- err
					return
				}
				if n != sent_n {
					err = errors.New("Expected to write " + strconv.Itoa(sent_n) +
					" bytes to client. But wrote " + strconv.Itoa(n) +
						" bytes. Moving on.")
					errChan <- err
					return
				} else {
					Logger.Debugf("Successfully wrote to Client")
				}
			}
		}
		err := errors.New("Stopped")
		errChan <- err
	}

	forwardFromClientToServer := func ()() {
		for !TDstate.proxy.stop {
			n, err := io.Copy(TDstate.servConn, TDstate.userConn)
			Logger.Debugf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10) +
				"] forwardFromClientToServer returns, bytes sent: " +
				strconv.FormatUint(uint64(n), 10))
			if err != nil {
				// TODO: maybe ignore other err?
				errChan <- err
				return
			}
		}
		errChan <- err
	}

	go forwardFromServerToClient()
	go forwardFromClientToServer()

	if err := <-errChan; err != nil && err.Error() != "MSG_CLOSE" {
		str_err := err.Error()

		// statistics
		if strings.Contains(str_err, "TapDance station didn't pick up the request") {
			TDstate.proxy.notPickedUp.inc()
		} else if strings.Contains(str_err, ": i/o timeout") {
			TDstate.proxy.timedOut.inc()
		}  else {
			TDstate.proxy.unexpectedError.inc()
		}

		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
			"] Redirect function returns, error: " + err.Error())
		return err
	} else {
		TDstate.proxy.closedGracefully.inc()
	}
	return nil
}
