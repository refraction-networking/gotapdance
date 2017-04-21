package tapdance

import (
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Connection-oriented state
type TapDanceFlow struct {
	// tunnel index and start time
	id      uint64
	startMs time.Time

	// reference to global proxy
	proxy *TapdanceProxy

	servConn *tapdanceConn
	userConn net.Conn
}

// constructor
func NewTapDanceFlow(proxy *TapdanceProxy, id uint64) *TapDanceFlow {
	state := new(TapDanceFlow)

	state.proxy = proxy
	state.id = id

	state.startMs = time.Now()

	Logger.Debugf("Created new TDState ", state)
	return state
}

func shotgunDialHelper(id uint64, o *sync.Once, wg *sync.WaitGroup, r chan<- *tapdanceConn, e chan<- error) {
	tmpResult, err := DialTapDance(id, nil)
	onlyOnce := func() {
		e <- err
		r <- tmpResult
	}
	if err == nil {
		o.Do(onlyOnce)
	}
	wg.Done()
}

func shotgunDialHelperCleanup(id uint64, o *sync.Once, wg *sync.WaitGroup, r chan<- *tapdanceConn, e chan<- error) {
	tmpResult, err := DialTapDance(id, nil)
	onlyOnce := func() {
		e <- err
		r <- tmpResult
	}
	if err == nil {
		o.Do(onlyOnce)
	} else {
		wg.Wait()
		o.Do(onlyOnce)
	}
}

func shotgunDial(id uint64) (*tapdanceConn, error) {
	o := sync.Once{}
	wg := sync.WaitGroup{}
	resultChan := make(chan *tapdanceConn)
	errChan := make(chan error)
	for i := 0; i < parallelDials-1; i++ {
		wg.Add(1)
		go shotgunDialHelper(id, &o, &wg, resultChan, errChan)
	}
	go shotgunDialHelperCleanup(id, &o, &wg, resultChan, errChan)
	e := <-errChan
	r := <-resultChan
	return r, e
}

func (TDstate *TapDanceFlow) Redirect() (err error) {
	TDstate.servConn, err = shotgunDial(TDstate.id)
	if err != nil {
		TDstate.userConn.Close()
		return
	}
	errChan := make(chan error)
	defer func() {
		TDstate.userConn.Close()
		TDstate.servConn.Close()
		_ = <-errChan // wait for second goroutine to close
	}()

	forwardFromServerToClient := func() {
		n, _err := io.Copy(TDstate.userConn, TDstate.servConn)
		Logger.Debugf(TDstate.servConn.idStr() +
			" forwardFromServerToClient returns, bytes sent: " +
			strconv.FormatUint(uint64(n), 10))
		if _err == nil {
			_err = errors.New("server returned without error")
		}
		errChan <- _err
		return
	}

	forwardFromClientToServer := func() {
		n, _err := io.Copy(TDstate.servConn, TDstate.userConn)
		Logger.Debugf(TDstate.servConn.idStr() +
			" forwardFromClientToServer returns, bytes sent: " +
			strconv.FormatUint(uint64(n), 10))
		if _err == nil {
			_err = errors.New("StoppedByUser")
		}
		errChan <- _err
		return
	}

	go forwardFromServerToClient()
	go forwardFromClientToServer()

	if err = <-errChan; err != nil {
		if err.Error() == "MSG_CLOSE" || err.Error() == "StoppedByUser" {
			Logger.Debugln("[Session " + strconv.FormatUint(uint64(TDstate.id), 10) +
				" Redirect function returns gracefully: " + err.Error())
			TDstate.proxy.closedGracefully.inc()
			err = nil
		} else {
			str_err := err.Error()

			// statistics
			if strings.Contains(str_err, "TapDance station didn't pick up the request") {
				TDstate.proxy.notPickedUp.inc()
			} else if strings.Contains(str_err, ": i/o timeout") {
				TDstate.proxy.timedOut.inc()
			} else {
				TDstate.proxy.unexpectedError.inc()
			}
		}
	}
	return
}
