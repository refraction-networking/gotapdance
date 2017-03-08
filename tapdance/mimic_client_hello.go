package tapdance

import (
	"github.com/zmap/zcrypto/tls"
	"net"
)

// List of ciphers we offer in Client Hello
// NOT A LIST OF CIPHER SUITES THAT ACTUALLY WORK
// Mimics Android
var TDOAndroidCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	tls.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_RC4_128_SHA,
}

//Mimics Firefox 50
var TDFirefox50Ciphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
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

func getZtlsConfig(Browser string, sni string) tls.Config {
	conf := tls.Config{}
	conf.RootCAs = Assets().GetRoots()
	conf.ServerName = sni
	switch Browser {
	default:
		fallthrough
	case "Firefox50":
		hello := tls.ClientFingerprintConfiguration{}
		hello.HandshakeVersion = 0x0303
		hello.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
		hello.CompressionMethods = []uint8{0}
		sni := tls.SNIExtension{[]string{}, true}
		ec := tls.SupportedCurvesExtension{[]tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521}}
		points := tls.PointFormatExtension{[]uint8{0}}
		st := tls.SessionTicketExtension{[]byte{}, true}
		alpn := tls.ALPNExtension{[]string{"h2", "http/1.1"}}
		sigs := tls.SignatureAlgorithmExtension{[]uint16{0x0401,
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
		hello.SessionCache = tls.NewLRUClientSessionCache(0)
		hello.CacheKey = &CacheKeyFunctor{}
		hello.Extensions = []tls.ClientExtension{&sni,
			&tls.ExtendedMasterSecretExtension{},
			&tls.SecureRenegotiationExtension{},
			&ec,
			&points,
			&st,
			&tls.NextProtocolNegotiationExtension{[]string{"h2", "http/1.1"}},
			&alpn,
			&tls.StatusRequestExtension{},
			&sigs,
		}
		conf.ClientFingerprintConfiguration = &hello
		return conf

	case "Android4.4":
		conf.ForceSuites = true
		hello := tls.ClientFingerprintConfiguration{}
		hello.HandshakeVersion = 0x0303
		hello.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
			tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_RC4_128_MD5,
			0x00ff}
		hello.CompressionMethods = []uint8{0}
		sni := tls.SNIExtension{[]string{}, true}
		st := tls.SessionTicketExtension{[]byte{}, true}
		sigs := tls.SignatureAlgorithmExtension{[]uint16{
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
		points := tls.PointFormatExtension{[]uint8{0}}
		ec := tls.SupportedCurvesExtension{[]tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}}
		hello.Extensions = []tls.ClientExtension{
			&sni,
			&points,
			&ec,
			&st,
			&sigs,
			&tls.NextProtocolNegotiationExtension{[]string{"h2", "http/1.1"}}}
		hello.SessionCache = tls.NewLRUClientSessionCache(0)
		hello.CacheKey = &CacheKeyFunctor{}
		conf.ClientFingerprintConfiguration = &hello
		return conf

	//Asterisk because we don't have Channel ID extension, which would require a tls PR
	case "Chrome47*":
		hello := tls.ClientFingerprintConfiguration{}
		hello.HandshakeVersion = 0x0303
		hello.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
		hello.CompressionMethods = []uint8{0}
		sni := tls.SNIExtension{[]string{}, true}
		ec := tls.SupportedCurvesExtension{[]tls.CurveID{tls.CurveP256, tls.CurveP384}}
		points := tls.PointFormatExtension{[]uint8{0}}
		st := tls.SessionTicketExtension{[]byte{}, true}
		alpn := tls.ALPNExtension{[]string{"http/1.1", "spdy/3.1", "h2"}}
		sigs := tls.SignatureAlgorithmExtension{[]uint16{0x0401,
			0x0601,
			0x0603,
			0x0501,
			0x0503,
			0x0401,
			0x0403,
			0x0301,
			0x0303,
			0x0201,
			0x0203,
		}}
		hello.SessionCache = tls.NewLRUClientSessionCache(0)
		hello.CacheKey = &CacheKeyFunctor{}
		hello.Extensions = []tls.ClientExtension{
			&tls.SecureRenegotiationExtension{},
			&sni,
			&tls.ExtendedMasterSecretExtension{},
			&st,
			&sigs,
			&tls.StatusRequestExtension{},
			&tls.NextProtocolNegotiationExtension{[]string{"http/1.1", "spdy/3.1", "h2"}},
			&tls.SCTExtension{},
			&alpn,
			&points,
			&ec,
		}
		conf.ClientFingerprintConfiguration = &hello
		return conf

	}
}
