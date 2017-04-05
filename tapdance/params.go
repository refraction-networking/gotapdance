package tapdance

import (
	"math"
	"time"
	"github.com/zmap/zcrypto/tls"
)

const timeoutMax = 30
const timeoutMin = 20

const sendLimitMax = 16 * 1024
const sendLimitMin = 16*1024 - 1984

const deadlineConnectTDStation = 15 // timeout for sending TD request and getting a response
const deadlineTCPtoDecoy = 10       // deadline to establish TCP connection to decoy
const waitForFINTimeout = 18        // time to wait for FIN to come back after socket shutdown

const maxInt16 = int16(^uint16(0) >> 1) // max msg size -> might have to chunk
const minInt16 = - maxInt16 - 1

const (
	TD_STATE_NEW = iota
	TD_STATE_CONNECTED
	TD_STATE_RECONNECT
	TD_STATE_CLOSED
)

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
