module github.com/refraction-networking/gotapdance

go 1.13

replace (
	github.com/Psiphon-Labs/chacha20 => github.com/Psiphon-Labs/chacha20 v0.2.1-0.20200128191310-899a4be52863
	github.com/Psiphon-Labs/quic-go => github.com/Psiphon-Labs/quic-go v0.14.1-0.20200306193310-474e74c89fab
	github.com/bifurcation/mint => github.com/bifurcation/mint v0.0.0-20180306135233-198357931e61
	github.com/cognusion/go-cache-lru => github.com/cognusion/go-cache-lru v0.0.0-20170419142635-f73e2280ecea
)

require (
	github.com/golang/protobuf v1.4.2
	github.com/jinzhu/copier v0.0.0-20190924061706-b57f9002281a
	github.com/mroth/weightedrand v0.2.1
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.5.0
	github.com/refraction-networking/utls v0.0.0-20190909200633-43c36d3c1f57
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507
	github.com/sirupsen/logrus v1.6.0
	golang.org/x/crypto v0.0.0-20200510223506-06a226fb4e37
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3
)
