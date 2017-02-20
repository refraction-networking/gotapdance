package tapdance

import (
	"github.com/zmap/zgrab/ztools/ztls"
	"net"
)

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

type CacheKeyFunctor struct {
}

func (f CacheKeyFunctor) Key(a net.Addr) string {
	return a.String()
}

func getZtlsConfig(Browser string) ztls.Config {
	switch Browser {
	default:
		fallthrough
	case "Firefox50":
		conf := ztls.Config{
			InsecureSkipVerify: true,
		}
		hello := ztls.ClientFingerprintConfiguration{}
		hello.HandshakeVersion = 0x0303

		hello.CipherSuites = []uint16{
			ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
		hello.CompressionMethods = []uint8{0}
		sni := ztls.SNIExtension{[]string{}, true}
		ec := ztls.SupportedCurvesExtension{[]ztls.CurveID{ztls.CurveP256, ztls.CurveP384, ztls.CurveP521}}
		points := ztls.PointFormatExtension{[]uint8{0}}
		st := ztls.SessionTicketExtension{[]byte{}, true}
		alpn := ztls.ALPNExtension{[]string{"h2", "http/1.1"}}
		sigs := ztls.SignatureAlgorithmExtension{[]uint16{0x0401,
			0x0501,
			0x0601,
			0x0201,
			0x0403,
			0x0503,
			0x0603,
			0x0203,
			0x0502,
			0x0402,
			0x0202,
		}}

		hello.SessionCache = ztls.NewLRUClientSessionCache(0)
		hello.CacheKey = &CacheKeyFunctor{}
		hello.Extensions = []ztls.ClientExtension{&sni,
			&ztls.ExtendedMasterSecretExtension{},
			&ztls.SecureRenegotiationExtension{},
			&ec,
			&points,
			&st,
			&ztls.NextProtocolNegotiationExtension{},
			&alpn,
			&ztls.StatusRequestExtension{},
			&sigs,
		}
		conf.ClientFingerprintConfiguration = &hello
		return conf
	case "Android4.4":
		conf := ztls.Config{
			InsecureSkipVerify: true,
		}
		hello := ztls.ClientFingerprintConfiguration{}
		hello.HandshakeVersion = 0x0303
		hello.CipherSuites = []uint16{
			ztls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			ztls.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			ztls.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
			ztls.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
			ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
			ztls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			ztls.TLS_RSA_WITH_RC4_128_SHA,
			ztls.TLS_RSA_WITH_RC4_128_MD5,
			0x00ff}

		hello.CompressionMethods = []uint8{0}
		sni := ztls.SNIExtension{[]string{}, true}
		st := ztls.SessionTicketExtension{[]byte{}, true}
		sigs := ztls.SignatureAlgorithmExtension{[]uint16{
			0x0601,
			0x0602,
			0x0603,
			0x0501,
			0x0502,
			0x0503,
			0x0401,
			0x0402,
			0x0403,
			0x0301,
			0x0302,
			0x0303,
			0x0201,
			0x0202,
			0x0203,
			0x0101,
		}}
		points := ztls.PointFormatExtension{[]uint8{0}}
		ec := ztls.SupportedCurvesExtension{[]ztls.CurveID{ztls.CurveP521, ztls.CurveP384, ztls.CurveP256}}
		hello.Extensions = []ztls.ClientExtension{
			&sni,
			&st,
			&sigs,
			&ztls.NextProtocolNegotiationExtension{},
			&points,
			&ec}
		hello.SessionCache = ztls.NewLRUClientSessionCache(0)
		hello.CacheKey = &CacheKeyFunctor{}
		conf.ClientFingerprintConfiguration = &hello
		return conf
		// Chrome?
	}
}
