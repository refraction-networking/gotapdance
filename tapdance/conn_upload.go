package tapdance

import (
	//	"github.com/SergeyFrolov/bsbuffer"
	"errors"
	"strconv"
	"sync"
	"time"
)

/*
TODO: It probably should have read flow that reads messages and then send "STAHP" to channel when read
TODO: we can avoid reconnecting if idle for too long
NOTE: DialRConn does NOT track amounts of uploaded data against upload limit, as it is currently
guaranteed to never exceed current min limit of 13kB.
Shall this ever change -- please take needed precautions and reconnect.
*/

// Used for writing data and session control messages
type tapdanceWConn struct {
	tdConn *Conn
	tdRaw  *tdRawConn

	headerBuf [6]byte

	writeSliceChan    chan []byte
	writeResultChan   chan IoOpResult
	writtenBytesTotal int

	yieldConfirmed chan struct{} // used by rConn to signal that flow was picked up

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func DialWConn(tdRaw tdRawConn, tdConn *Conn) (*tapdanceWConn, error) {
	if tdRaw.tlsConn == nil {
		// dial tdRawConn if not dialed yet
		err := tdRaw.Dial()
		if err != nil {
			return nil, errors.New(tdRaw.idStr() + err.Error())
		}
	}

	wConn := tapdanceWConn{tdRaw: &tdRaw, tdConn: tdConn}
	wConn.yieldConfirmed = make(chan struct{}, 1)
	wConn.closed = make(chan struct{})
	wConn.writeSliceChan = make(chan []byte)
	wConn.writeResultChan = make(chan IoOpResult)

	go wConn.spawnWriterEngine()

	return &wConn, nil
}

// wait for rConn to confirm that flow was noticed
func (wConn *tapdanceWConn) WaitForYieldConfirmation() error {
	// camouflage issue
	timeout := time.After(20 * time.Second)
	select {
	case <-timeout:
		return errors.New("yeild confirmation timeout")
	case <-wConn.yieldConfirmed:
		Logger().Infoln(wConn.idStr() +
			" Successfully received yield confirmation from reader flow!")
		return nil
	case <-wConn.closed:
		return wConn.closeErr
	}
}

func (wConn *tapdanceWConn) getDecoyTimeout() <-chan time.Time {
	amortizationVal := 0.9
	const minSubtrahend = 50
	const maxSubtrahend = 9500
	secsToWait := int(float64(wConn.tdRaw.decoySpec.GetTimeout())*amortizationVal) -
		getRandInt(minSubtrahend, maxSubtrahend)
	return time.After(time.Now().
		Add(time.Millisecond * time.Duration(secsToWait)).
		Sub(wConn.tdRaw.establishedAt))
}

type IoOpResult struct {
	err error
	n   int
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (wConn *tapdanceWConn) spawnWriterEngine() {
	defer close(wConn.writeResultChan)
	decoyTimeout := wConn.getDecoyTimeout()
	for {
		select {
		case <-decoyTimeout:
			wConn.tdRaw.writeTransition(C2S_Transition_C2S_EXPECT_RECONNECT)
			err := wConn.tdRaw.Redial()
			wConn.writtenBytesTotal = 0
			if err != nil {
				wConn.closeWithErrorOnce(err)
				return
			}
			decoyTimeout = wConn.getDecoyTimeout()
		case <-wConn.closed:
			return
		case b := <-wConn.writeSliceChan:
			// current chunking policy: never do it in POST flows, as we are allowed
			// to send up to 1MB, e.g. something fishy is going on
			if len(b)+6+1024 > wConn.tdRaw.ContentLength-wConn.writtenBytesTotal {
				// 6 is max header size (protobufs aren't sent here though)
				// 1024 is max transition message size
				wConn.tdRaw.writeTransition(C2S_Transition_C2S_EXPECT_RECONNECT)
				err := wConn.tdRaw.Redial()
				wConn.writtenBytesTotal = 0
				if err != nil {
					wConn.closeWithErrorOnce(err)
					return
				}
			}

			if len(b)+6+1024 > wConn.tdRaw.ContentLength {
				wConn.closeWithErrorOnce(errors.New("tried to send too much (" +
					strconv.Itoa(len(b)) + " bytes)"))
				return
			}

			// TODO: outerProto limit on data size
			bWithHeader := getMsgWithHeader(msg_raw_data, b) // TODO: optimize!
			ioResult := IoOpResult{}
			ioResult.n, ioResult.err = wConn.tdRaw.tlsConn.Write(bWithHeader)
			wConn.writtenBytesTotal += ioResult.n
			select {
			case wConn.writeResultChan <- ioResult:
			case <-wConn.closed:
				return
			}
		}
	}
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (wConn *tapdanceWConn) Write(b []byte) (int, error) {
	// deadline?
	select {
	case wConn.writeSliceChan <- b:
	case <-wConn.closed:
		return 0, wConn.closeErr
	}
	select {
	case r := <-wConn.writeResultChan:
		return r.n, r.err
	case <-wConn.closed:
		return 0, wConn.closeErr
	}
}

func (wConn *tapdanceWConn) AcquireYield() error {
	_, err := wConn.tdRaw.writeTransition(C2S_Transition_C2S_ACQUIRE_UPLOAD)
	if err != nil {
		Logger().Infoln(wConn.idStr() + " Failed attempt to acquire upload:" + err.Error())
	} else {
		Logger().Infoln(wConn.idStr() + " Sent acquire upload request")
	}
	return err
}

// Closes connection, channel and sets error ONCE, e.g. error won't be overwritten
func (wConn *tapdanceWConn) closeWithErrorOnce(err error) {
	if err != nil {
		// safeguard, shouldn't happen
		err = errors.New("closed with nil error!")
	}
	wConn.closeOnce.Do(func() {
		wConn.closeErr = errors.New(wConn.idStr() + " " + err.Error())
		close(wConn.closed)
		wConn.tdRaw.Close()
	})
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (wConn *tapdanceWConn) Close() error {
	wConn.closeWithErrorOnce(errors.New("closed externally"))
	return wConn.closeErr
}

func (wConn *tapdanceWConn) idStr() string {
	return wConn.tdRaw.idStr()
}
