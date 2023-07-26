module github.com/refraction-networking/gotapdance

go 1.18

replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230725223418-2d2e5b4a16ba

require (
	github.com/golang/protobuf v1.5.3
	github.com/jinzhu/copier v0.3.5
	github.com/keltia/ripe-atlas v0.0.0-20211221125000-f6eb808d5dc6
	github.com/pelletier/go-toml v1.9.5
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.7.0
	github.com/refraction-networking/conjure v0.6.0-dtlsbeta
	github.com/refraction-networking/ed25519 v0.1.2
	github.com/refraction-networking/utls v1.2.0
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.11.0
	golang.org/x/net v0.12.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/andybalholm/brotli v1.0.5-0.20220518190645-786ec621f618 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/felixge/fgprof v0.9.3 // indirect
	github.com/flynn/noise v1.0.0 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20211214055906-6f57359322fd // indirect
	github.com/hashicorp/golang-lru v0.6.0 // indirect
	github.com/keltia/proxy v0.9.3 // indirect
	github.com/klauspost/compress v1.15.12 // indirect
	github.com/libp2p/go-reuseport v0.3.0 // indirect
	github.com/mingyech/dtls v0.1.0 // indirect
	github.com/mingyech/transport v0.1.1 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/oschwald/geoip2-golang v1.8.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pebbe/zmq4 v1.2.9 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/sctp v1.8.7 // indirect
	github.com/pion/stun v0.3.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/refraction-networking/obfs4 v0.1.1 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.4.0 // indirect
	golang.org/x/sys v0.10.0 // indirect
	golang.org/x/text v0.11.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
