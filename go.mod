module github.com/refraction-networking/gotapdance

go 1.18

require (
	github.com/jinzhu/copier v0.3.5
	github.com/keltia/ripe-atlas v0.0.0-20211221125000-f6eb808d5dc6
	github.com/pelletier/go-toml v1.9.5
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.7.0
	github.com/refraction-networking/conjure v0.7.0
	github.com/refraction-networking/ed25519 v0.1.2
	github.com/refraction-networking/utls v1.3.3
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.13.0
	golang.org/x/net v0.15.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/felixge/fgprof v0.9.3 // indirect
	github.com/flynn/noise v1.0.0 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20211214055906-6f57359322fd // indirect
	github.com/keltia/proxy v0.9.3 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/sctp v1.8.8 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v2 v2.2.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pion/dtls/v2 => github.com/mingyech/dtls/v2 v2.0.0

replace github.com/pion/transport/v2 => github.com/mingyech/transport/v2 v2.0.0

replace github.com/refraction-networking/conjure => github.com/refraction-networking/conjure v0.7.1-0.20230918140746-1a71eb3e313e
