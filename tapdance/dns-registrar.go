package tapdance

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pion/stun"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/requester"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

type DNSRegistrar struct {
	req             *requester.Requester
	maxTries        int
	connectionDelay time.Duration
	bidirectional   bool
	ip              []byte
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
	return NewDNSRegistrar(*conf.DnsRegMethod, target, *conf.Domain, pubkey, *conf.UtlsDistribution, maxTries, bidirectional, delay, *conf.StunServer)
}

// NewDNSRegistrar creates a DNSRegistrar.
func NewDNSRegistrar(regType pb.DnsRegMethod, target string, domain string, pubkey []byte, utlsDistribution string, maxTries int, bidirectional bool, delay time.Duration, stun_server string) (*DNSRegistrar, error) {
	r := &DNSRegistrar{}
	r.maxTries = maxTries
	r.bidirectional = bidirectional
	r.connectionDelay = delay
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

	switch regType {
	case pb.DnsRegMethod_UDP:
		remoteAddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			return nil, err
		}
		r.req, err = requester.NewUDPRequester(remoteAddr, domain, pubkey)
		if err != nil {
			return nil, err
		}
	case pb.DnsRegMethod_DOT:
		r.req, err = requester.NewDoTRequester(target, domain, pubkey, utlsDistribution)
		if err != nil {
			return nil, err
		}
	case pb.DnsRegMethod_DOH:
		r.req, err = requester.NewDoHRequester(target, domain, pubkey, utlsDistribution)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unkown reg method")
	}

	r.ip, err = getPublicIp(stun_server)
	if err != nil {
		Logger().Errorf("Failed to get public IP: [%v]", err)
		return nil, err
	}

	return r, nil
}

// Register prepares and sends the registration request.
func (r DNSRegistrar) Register(cjSession *ConjureSession, ctx context.Context) (*ConjureReg, error) {
	Logger().Debugf("%v registering via DNSRegistrar", cjSession.IDString())

	var reg *ConjureReg

	if r.bidirectional {
		reg = &ConjureReg{
			sessionIDStr: cjSession.IDString(),
			keys:         cjSession.Keys,
			stats:        &pb.SessionStats{},
			// phantom4:       phantom4,
			// phantom6:       phantom6,
			v6Support:      cjSession.V6Support.include,
			covertAddress:  cjSession.CovertAddress,
			transport:      cjSession.Transport,
			TcpDialer:      cjSession.TcpDialer,
			useProxyHeader: cjSession.UseProxyHeader,
		}
	} else {

		phantom4, phantom6, err := SelectPhantom(cjSession.Keys.ConjureSeed, cjSession.V6Support.include)
		if err != nil {
			Logger().Warnf("%v failed to select Phantom: %v", cjSession.IDString(), err)
			return nil, err
		}

		// [reference] Prepare registration
		reg = &ConjureReg{
			sessionIDStr:   cjSession.IDString(),
			keys:           cjSession.Keys,
			stats:          &pb.SessionStats{},
			phantom4:       phantom4,
			phantom6:       phantom6,
			v6Support:      cjSession.V6Support.include,
			covertAddress:  cjSession.CovertAddress,
			transport:      cjSession.Transport,
			TcpDialer:      cjSession.TcpDialer,
			useProxyHeader: cjSession.UseProxyHeader,
		}
	}

	c2s := reg.generateClientToStation()

	protoPayload := pb.C2SWrapper{
		SharedSecret:        cjSession.Keys.SharedSecret,
		RegistrationPayload: c2s,
		RegistrationAddress: r.ip,
	}

	if r.bidirectional {
		protoPayload.RegistrationSource = pb.RegistrationSource_BidirectionalDNS.Enum()
	} else {
		protoPayload.RegistrationSource = pb.RegistrationSource_DNS.Enum()
	}

	payload, err := proto.Marshal(&protoPayload)
	if err != nil {
		Logger().Warnf("%v failed to marshal ClientToStation payload: %v", cjSession.IDString(), err)
		return nil, err
	}

	Logger().Debugf("%v DNS payload length: [%d]", cjSession.IDString(), len(payload))

	for i := 0; i < r.maxTries; i++ {
		response, err := r.req.RequestAndRecv(payload)
		if err != nil {
			Logger().Warnf("%v error in sending request to DNS registrar: %v", cjSession.IDString(), err)
			continue
		}

		// If unidirectional, do no check response
		if !r.bidirectional {
			sleepWithContext(ctx, r.connectionDelay)
			return reg, nil
		}

		dnsResp := &pb.DnsResponse{}
		err = proto.Unmarshal(response, dnsResp)
		if err != nil {
			Logger().Warnf("%v error in storing Registrtion Response protobuf: %v", cjSession.IDString(), err)
			continue
		}
		if !dnsResp.GetSuccess() {
			Logger().Warnf("%v Registrar indicates that registration failed", cjSession.IDString())
			continue
		}
		Logger().Debugf("%v DNS registration succeeded", cjSession.IDString())
		sleepWithContext(ctx, r.connectionDelay)

		if dnsResp.GetClientconfOutdated() {
			Logger().Warnf("%v Registrar indicates that ClinetConf is outdated", cjSession.IDString())
		}
		conjReg := r.unpackRegResp(reg, dnsResp.GetBidirectionalResponse())
		return conjReg, nil
	}
	return nil, errors.New("attempts on dns registration failed")
}

func (r DNSRegistrar) unpackRegResp(reg *ConjureReg, regResp *pb.RegistrationResponse) *ConjureReg {
	if reg.v6Support == v4 {
		// Save the ipv4address in the Conjure Reg struct (phantom4) to return
		ip4 := make(net.IP, 4)
		addr4 := regResp.GetIpv4Addr()
		binary.BigEndian.PutUint32(ip4, addr4)
		reg.phantom4 = &ip4
	} else if reg.v6Support == v6 {
		// Save the ipv6address in the Conjure Reg struct (phantom6) to return
		addr6 := net.IP(regResp.GetIpv6Addr())
		reg.phantom6 = &addr6
	} else {
		// Case where cjSession.V6Support == both
		// Save the ipv4address in the Conjure Reg struct (phantom4) to return
		ip4 := make(net.IP, 4)
		addr4 := regResp.GetIpv4Addr()
		binary.BigEndian.PutUint32(ip4, addr4)
		reg.phantom4 = &ip4

		// Save the ipv6address in the Conjure Reg struct (phantom6) to return
		addr6 := net.IP(regResp.GetIpv6Addr())
		reg.phantom6 = &addr6
	}

	// Client config -- check if not nil in the registration response
	if regResp.GetClientConf() != nil {
		currGen := Assets().GetGeneration()
		incomingGen := regResp.GetClientConf().GetGeneration()
		Logger().Debugf("received clientconf in regResponse w/ gen %d", incomingGen)
		if currGen < incomingGen {
			Logger().Debugf("Updating clientconf %d -> %d", currGen, incomingGen)
			_err := Assets().SetClientConf(regResp.GetClientConf())
			if _err != nil {
				Logger().Warnf("could not set ClientConf in bidirectional API: %v", _err.Error())
			}
		}
	}

	return reg
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

	Logger().Debugf("Public IP is: [%s]", ip.String())

	return ip.To4(), nil
}
