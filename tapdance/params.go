package tapdance

import (
	"math"
	"time"
)

const timeoutMax = 30
const timeoutMin = 20

const sendLimitMax = 16 * 1024
const sendLimitMin = 16*1024 - 1984

const deadlineConnectTDStation = 15 // timeout for sending TD request and getting a response
const deadlineTCPtoDecoy = 10       // deadline to establish TCP connection to decoy
const waitForFINTimeout = 18        // time to wait for FIN to come back after socket shutdown

const (
	MSG_DATA = iota // iota auto increments
	MSG_INIT
	MSG_RECONNECT
	MSG_CLOSE
)

const (
	TD_STATE_NEW = iota
	TD_STATE_CONNECTED
	TD_STATE_RECONNECT
	TD_STATE_CLOSED
)

// How much time to sleep on trying to connect to decoys to prevent overwhelming them
func sleepBeforeConnect(attempt int) (waitTime <-chan time.Time) {
	if attempt >= 2 { // return nil for first 2 attempts
		waitTime = time.After(time.Second *
			time.Duration(math.Pow(3, float64(attempt-1))))
	}
	return
}
