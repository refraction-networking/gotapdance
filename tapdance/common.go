package tapdance

import (
	"errors"
	"github.com/refraction-networking/utls"
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
const waitForFINDie = 22000 // time to wait before crashing

const maxInt16 = int16(^uint16(0) >> 1) // max msg size -> might have to chunk
//const minInt16 = int16(-maxInt16 - 1)

type flowType int8

const (
	flowUpload        flowType = 0x1
	flowReadOnly      flowType = 0x2
	flowBidirectional flowType = 0x4
)

func (m *flowType) Str() string {
	switch *m {
	case flowUpload:
		return "FlowUpload"
	case flowReadOnly:
		return "FlowReadOnly"
	case flowBidirectional:
		return "FlowBidirectional"
	default:
		return strconv.Itoa(int(*m))
	}
}

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

type tdTagType int8

const (
	tagHttpGetIncomplete  tdTagType = 0
	tagHttpGetComplete    tdTagType = 1
	tagHttpPostIncomplete tdTagType = 2
)

func (m *tdTagType) Str() string {
	switch *m {
	case tagHttpGetIncomplete:
		return "HTTP GET Incomplete"
	case tagHttpGetComplete:
		return "HTTP GET Complete"
	case tagHttpPostIncomplete:
		return "HTTP POST Incomplete"
	default:
		return strconv.Itoa(int(*m))
	}
}

// First byte of tag is for FLAGS
// bit 0 (1 << 7) determines if flow is bidirectional(0) or upload-only(1)
// bits 1-6 are unassigned
// bit 7 (1 << 0) signals to use TypeLen outer proto
var (
	tdFlagUploadOnly = uint8(1 << 7)
	tdFlagUseTIL     = uint8(1 << 0)
)

// List of actually supported ciphers(not a list of offered ciphers!)
// Essentially all working AES_GCM_128 ciphers
var TDSupportedCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
}

func forceSupportedCiphersFirst(suites []uint16) []uint16 {
	swapSuites := func(i, j int) {
		if i == j {
			return
		}
		tmp := suites[j]
		suites[j] = suites[i]
		suites[i] = tmp
	}
	lastSupportedCipherIdx := 0
	for i := range suites {
		for _, supportedS := range TDSupportedCiphers {
			if suites[i] == supportedS {
				swapSuites(i, lastSupportedCipherIdx)
				lastSupportedCipherIdx += 1
			}
		}
	}
	alwaysSuggestedSuite := tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	for i := range suites {
		if suites[i] == alwaysSuggestedSuite {
			return suites
		}
	}
	return append([]uint16{alwaysSuggestedSuite}, suites[lastSupportedCipherIdx:]...)
}

// How much time to sleep on trying to connect to decoys to prevent overwhelming them
func sleepBeforeConnect(attempt int) (waitTime <-chan time.Time) {
	if attempt >= 2 { // return nil for first 2 attempts
		waitTime = time.After(time.Second *
			time.Duration(math.Pow(3, float64(attempt-1))))
	}
	return
}
