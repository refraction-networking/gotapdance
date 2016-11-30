package tapdance

import (
	"net"
	"strconv"
	"time"
	"io"
	"errors"
)

const (
	MSG_DATA = iota // iota auto increments
	MSG_INIT
	MSG_RECONNECT
	MSG_CLOSE
)


// Connection-oriented state
type TDConnState struct {
	realHost     string // todo Do I need it?
	realPort     int

			    // tunnel index and start time
	id           uint
	startMs      uint64
	name         string

			    // reference to global proxy
	proxy        *TapdanceProxy

	servConn     *tapdanceConn
	userConn     net.Conn

			    /* Set to 1 as soon as we learn (from proxy channel) that
			     we need to. This keeps a ISREMOTE EV_ERROR or EOF from cleaning
			     up the state */
	retryConn    int

			    /* Maximum amount of data we can send to the station
			     before we should tear-down the connection for a new one
			     with the same remote_conn_id */

};

// constructor
func NewTapdanceState(proxy *TapdanceProxy, id uint) *TDConnState {
	state := new(TDConnState)

	state.proxy = proxy
	state.id = id

	state.startMs = uint64(timeMs())

	state.name = "tunnel" + strconv.FormatUint(uint64(state.id), 10)

	Logger.Debugf("Created new TDState ", state)
	return state
}

func (TDstate *TDConnState) WriteToClient(request []byte) (err error) {
	// TODO: remove this function
	// Used to shove data back to Client in Redirect phase
	//servConn

	// TODO: https://blog.filippo.io/the-complete-guide-to-go-net-http-timeouts/
	TDstate.userConn.SetWriteDeadline(time.Now().Add(time.Second * 2)) // Timeout in 2 secs
	Logger.Debugf("Trying to write to Client: ", string(request))
	n, err := TDstate.userConn.Write(request)
	if err != nil {
		return
	}
	if n != len(request) {
		Logger.Warningf("Expected to write " + strconv.Itoa(len(request)) + " bytes to client." +
		"But wrote " + strconv.Itoa(n) + " bytes. Moving on.")
		return
	} else {
		Logger.Debugf("Successfully wrote to Client")
	}
	return
}

func (TDstate *TDConnState) Redirect() (err error) {
	TDstate.servConn, err = DialTapDance(TDstate.id,
		&TDstate.proxy.stationPubkey, TDstate.proxy.roots)
	if err != nil {
		return
	}
	errChan := make(chan error)
	defer TDstate.userConn.Close()
	defer TDstate.servConn.Close()

	forwardFromServerToClient := func ()() {
		var b []byte
		for !TDstate.proxy.stop {
			n, err := TDstate.servConn.Read(b)
			if err != nil {
				errChan <- err
				return
			}
			if n > 0 {
				err = TDstate.WriteToClient(b[:n])
				if err != nil {
					errChan <- err
					return
				}
			}
		}
		err := errors.New("Stopped")
		errChan <- err
	}

	forwardFromClientToServer := func ()() {
		n, err := io.Copy(TDstate.servConn, TDstate.userConn)
		Logger.Debugf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
			"] forwardFromClientToServer returns, bytes sent: " +
			strconv.FormatUint(uint64(n), 10))
		errChan <- err
		return
	}

	go forwardFromServerToClient()
	go forwardFromClientToServer()

	if err := <-errChan; err != nil && err.Error() != "EOF" && err.Error() != "Stopped" {
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(TDstate.id), 10)  +
			"] Redirect function returns, error: " + err.Error())
		return err
	}
	//TODO: don't print on graceful close
	return nil
}
