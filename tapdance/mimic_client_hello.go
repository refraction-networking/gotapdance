package tapdance

import "github.com/zmap/zgrab/ztools/ztls"

// List of ciphers we offer in Client Hello
// NOT A LIST OF CIPHER SUITES THAT ACTUALLY WORK
// Mimics Android
var TDOAndroidCiphers = []uint16{
	ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	ztls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	ztls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	ztls.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	ztls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	ztls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
	ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_RSA_WITH_RC4_128_SHA,
}

//Mimics Firefox 50
var TDFirefox50Ciphers = []uint16{
	ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	0xc02c,
	0xc030,
	0xc00a,
	0xc009,
	0xc013,
	0xc014,
	0x0033,
	0x0039,
	0x002f,
	0x0035,
	0x000a,
}

func getZtlsConfig(Browser string) ztls.Config {
	switch Browser {
	default:
		fallthrough
	case "Firefox50":
		return ztls.Config{
			ForceSessionTicketExt:  true,
			CipherSuites:           TDFirefox50Ciphers,
			SessionTicketsDisabled: false,
			NextProtos:             []string{"h2", "http/1.1"},
			ExtendedMasterSecret:   true,
		}
		// Android is TODO: capture extensions
		// Chrome?
	}

}
