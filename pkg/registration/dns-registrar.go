package registration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pion/stun"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/requester"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
)

var (
	ErrRegFailed = errors.New("registration failed")
)

type DNSRegistrar struct {
	req             *requester.Requester
	maxTries        int
	connectionDelay time.Duration
	bidirectional   bool
	ip              []byte
	logger          logrus.FieldLogger
}

// NewDNSRegistrarFromConf creates a DNSRegistrar from DnsRegConf protobuf. Uses the pubkey in conf as default. If it is not supplied (nil), uses fallbackKey instead.
func NewDNSRegistrarFromConf(conf *pb.DnsRegConf, bidirectional bool, delay time.Duration, maxTries int, fallbackKey []byte) (*DNSRegistrar, error) {
	pubkey := conf.Pubkey
	if pubkey == nil {
		pubkey = fallbackKey
	}
	target := ""
	switch *conf.DnsRegMethod {
	case pb.DnsRegMethod_UDP:
		target = *conf.UdpAddr
	case pb.DnsRegMethod_DOT:
		target = *conf.DotAddr
	case pb.DnsRegMethod_DOH:
		target = *conf.DohUrl
	default:
		return nil, errors.New("unkown reg method in conf")
	}
	return NewDNSRegistrar(*conf.DnsRegMethod, target, *conf.Domain, pubkey, *conf.UtlsDistribution, maxTries, bidirectional, delay, *conf.StunServer, nil)
}

// NewDNSRegistrar creates a DNSRegistrar.
func NewDNSRegistrar(regType pb.DnsRegMethod, target string, domain string, pubkey []byte, utlsDistribution string, maxTries int, bidirectional bool, delay time.Duration, stun_server string, dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) (*DNSRegistrar, error) {
	var err error
	if utlsDistribution == "" {
		return nil, errors.New("utlsDistribution must be specified")
	}
	if domain == "" {
		return nil, errors.New("domain must be specified")
	}
	if pubkey == nil {
		return nil, errors.New("server public key must be provided")
	}

	var req *requester.Requester

	switch regType {
	case pb.DnsRegMethod_UDP:
		remoteAddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			return nil, err
		}
		req, err = requester.NewUDPRequester(remoteAddr, domain, pubkey)
		if err != nil {
			return nil, err
		}
	case pb.DnsRegMethod_DOT:
		req, err = requester.NewDoTRequester(target, domain, pubkey, utlsDistribution, dialContext)
		if err != nil {
			return nil, err
		}
	case pb.DnsRegMethod_DOH:
		req, err = requester.NewDoHRequester(target, domain, pubkey, utlsDistribution)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unkown reg method")
	}

	ip, err := getPublicIp(stun_server)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP: %w", err)
	}

	return &DNSRegistrar{
		req:             req,
		ip:              ip,
		maxTries:        maxTries,
		bidirectional:   bidirectional,
		connectionDelay: delay,
		logger:          tapdance.Logger().WithField("registrar", "DNS"),
	}, nil
}

// registerUnidirectional sends unidirectional registration data to the registration server
func (r *DNSRegistrar) registerUnidirectional(cjSession *tapdance.ConjureSession) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "unidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.UnidirectionalRegData(pb.RegistrationSource_DNS.Enum())

	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, ErrRegFailed
	}

	protoPayload.RegistrationAddress = r.ip

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, ErrRegFailed
	}

	logger.Debugf("DNS payload length: %d", len(payload))

	for i := 0; i < r.maxTries; i++ {
		logger := logger.WithField("attempt", strconv.Itoa(i+1)+"/"+strconv.Itoa(r.maxTries))
		_, err := r.req.RequestAndRecv(payload)
		if err != nil {
			logger.Warnf("error in registration attempt: %v", err)
			continue
		}

		// for unidirectional registration, do not check for response and immediatly return
		logger.Debugf("registration succeeded")
		return reg, nil
	}

	logger.WithField("maxTries", r.maxTries).Warnf("all registration attempt(s) failed")

	return nil, ErrRegFailed

}

// registerBidirectional sends bidirectional registration data to the registration server and reads the response
func (r *DNSRegistrar) registerBidirectional(cjSession *tapdance.ConjureSession) (*tapdance.ConjureReg, error) {

	logger := r.logger.WithFields(logrus.Fields{"type": "bidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.BidirectionalRegData(pb.RegistrationSource_BidirectionalDNS.Enum())

	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, ErrRegFailed
	}

	protoPayload.RegistrationAddress = r.ip

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, ErrRegFailed
	}

	logger.Debugf("DNS payload length: %d", len(payload))

	for i := 0; i < r.maxTries; i++ {
		logger := logger.WithField("attempt", strconv.Itoa(i+1)+"/"+strconv.Itoa(r.maxTries))

		bdResponse, err := r.req.RequestAndRecv(payload)
		if err != nil {
			logger.Warnf("error in sending request to DNS registrar: %v", err)
			continue
		}

		dnsResp := &pb.DnsResponse{}
		err = proto.Unmarshal(bdResponse, dnsResp)
		if err != nil {
			logger.Warnf("error in storing Registrtion Response protobuf: %v", err)
			continue
		}
		if !dnsResp.GetSuccess() {
			logger.Warnf("registrar indicates that registration failed")
			continue
		}
		if dnsResp.GetClientconfOutdated() {
			logger.Warnf("registrar indicates that ClinetConf is outdated")
		}

		err = reg.UnpackRegResp(dnsResp.GetBidirectionalResponse())
		if err != nil {
			logger.Warnf("failed to unpack registration response: %v", err)
			continue
		}
		return reg, nil
	}

	logger.WithField("maxTries", r.maxTries).Warnf("all registration attemps failed")

	return nil, ErrRegFailed
}

// Register prepares and sends the registration request.
func (r *DNSRegistrar) Register(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {

	defer sleepWithContext(ctx, r.connectionDelay)

	if r.bidirectional {
		return r.registerBidirectional(cjSession)
	}
	return r.registerUnidirectional(cjSession)
}

func getPublicIp(server string) ([]byte, error) {

	c, err := stun.Dial("udp4", server)
	if err != nil {
		return nil, errors.New("Failed to connect to STUN server: " + err.Error())
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	ip := net.IP{}

	err = c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}

		var xorAddr stun.XORMappedAddress
		err = xorAddr.GetFrom(res.Message)
		if err != nil {
			return
		}

		ip = xorAddr.IP
	})

	if err != nil {
		err = errors.New("Failed to get IP address from STUN: " + err.Error())
	}

	return ip.To4(), nil
}

func sleepWithContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
