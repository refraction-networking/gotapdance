module github.com/refraction-networking/gotapdance

go 1.22.0

toolchain go1.24.1

require (
	github.com/jinzhu/copier v0.4.0
	github.com/keltia/ripe-atlas v0.0.0-20211221125000-f6eb808d5dc6
	github.com/pelletier/go-toml v1.9.5
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.7.0
	github.com/refraction-networking/conjure v0.7.12-0.20250520170513-22f6cf9e6e66
	github.com/refraction-networking/ed25519 v0.1.2
	github.com/refraction-networking/utls v1.6.7
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure v0.0.0-20250401212049-c593391b702a
	golang.org/x/crypto v0.33.0
	golang.org/x/net v0.35.0
	google.golang.org/protobuf v1.36.5
)

require (
	filippo.io/bigmod v0.0.3 // indirect
	filippo.io/keygen v0.0.0-20240718133620-7f162efbbd87 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/felixge/fgprof v0.9.4 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20240618054019-d3b898a103f8 // indirect
	github.com/keltia/proxy v0.9.5 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/pion/dtls/v2 v2.2.12 // indirect
	github.com/pion/logging v0.2.3 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/sctp v1.8.37 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v2 v2.2.10 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/ptutil v0.0.0-20250130151315-efaf4e0ec0d3 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2 v2.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pion/dtls/v2 => github.com/mingyech/dtls/v2 v2.0.0

replace github.com/pion/transport/v2 => github.com/mingyech/transport/v2 v2.0.0

replace gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure => gitlab.torproject.org/onyinyang/conjure v0.0.0-20250403173837-5b5bb3154613
