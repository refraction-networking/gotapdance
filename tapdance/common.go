package tapdance

import (
	"errors"
	"github.com/zmap/zcrypto/tls"
	"math"
	"strconv"
	"time"
)

const timeoutMax = 30000
const timeoutMin = 20000

const sendLimitMax = 15614
const sendLimitMin = 14400

const deadlineConnectTDStation = 15 // timeout for sending TD request and getting a response
const deadlineTCPtoDecoy = 10       // deadline to establish TCP connection to decoy

// during reconnects we send FIN to server and wait until we get FIN back:
const waitForFINSendRST = 13 // time to wait before sending RST
const waitForFINDie = 22     // time to wait before crashing

const maxInt16 = int16(^uint16(0) >> 1) // max msg size -> might have to chunk
const minInt16 = int16(-maxInt16 - 1)

const (
	TD_STATE_NEW = iota
	TD_STATE_CONNECTED
	TD_STATE_RECONNECT
	TD_STATE_CLOSED
)

type MsgType int8

const (
	msg_raw_data MsgType = 1
	msg_protobuf MsgType = 2
)

func (m *MsgType) Str() string {
	switch *m {
	case msg_raw_data:
		return "msg_raw_data"
	case msg_protobuf:
		return "msg_protobuf"
	default:
		return strconv.Itoa(int(*m))
	}
}

var errMsgClose = errors.New("MSG CLOSE")

type TdTagType int8

const (
	HTTP_GET_INCOMPLETE TdTagType = 0
	HTTP_POST_COMPLETE  TdTagType = 1
)

func (m *TdTagType) Str() string {
	switch *m {
	case HTTP_GET_INCOMPLETE:
		return "HTTP_GET_INCOMPLETE"
	case HTTP_POST_COMPLETE:
		return "HTTP_POST_COMPLETE"
	default:
		return strconv.Itoa(int(*m))
	}
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

// How much time to sleep on trying to connect to decoys to prevent overwhelming them
func sleepBeforeConnect(attempt int) (waitTime <-chan time.Time) {
	if attempt >= 2 { // return nil for first 2 attempts
		waitTime = time.After(time.Second *
			time.Duration(math.Pow(3, float64(attempt-1))))
	}
	return
}
