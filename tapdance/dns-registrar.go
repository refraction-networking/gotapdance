package tapdance

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/mingyech/conjure-dns-registrar/pkg/requester"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

type DNSRegistrar struct {
	req           *requester.Requester
	maxTries      int
	bidirectional bool
	ip            []byte
}

func NewDNSRegistrarFromConf(conf *pb.DnsRegConf, bidirectional bool) (*DNSRegistrar, error) {
	switch *conf.DnsRegMethod {
	case pb.DnsRegMethod_UDP:
		return NewDNSRegistrar(*conf.UdpAddr, "", "", *conf.Domain, conf.Pubkey, *conf.UtlsDistribution, int(*conf.MaxTries), bidirectional)
	case pb.DnsRegMethod_DOT:
		return NewDNSRegistrar("", *conf.DotAddr, "", *conf.Domain, conf.Pubkey, *conf.UtlsDistribution, int(*conf.MaxTries), bidirectional)
	case pb.DnsRegMethod_DOH:
		return NewDNSRegistrar("", "", *conf.DohUrl, *conf.Domain, conf.Pubkey, *conf.UtlsDistribution, int(*conf.MaxTries), bidirectional)
	}
	return nil, errors.New("unkown reg method in conf")
}

func NewDNSRegistrar(udpAddr string, dotAddr string, dohUrl string, domain string, pubkey []byte, utlsDistribution string, maxTries int, bidirectional bool) (*DNSRegistrar, error) {
	r := &DNSRegistrar{}
	r.maxTries = maxTries
	r.bidirectional = bidirectional
	var err error
	if utlsDistribution == "" {
		utlsDistribution = "3*Firefox_65,1*Firefox_63,1*iOS_12_1"
	}
	if domain == "" {
		return nil, errors.New("domain must be specified")
	}
	if pubkey == nil {
		return nil, errors.New("server public key must be provided")
	}
	if udpAddr != "" {
		remoteAddr, err := net.ResolveUDPAddr("udp", udpAddr)
		if err != nil {
			return nil, err
		}
		r.req, err = requester.NewUDPRequester(remoteAddr, domain, pubkey)
		if err != nil {
			return nil, err
		}
	}
	if dohUrl != "" || dotAddr != "" {
		if r.req != nil {
			return nil, errors.New("only one of udpAddr, dohUrl, dotAddr may be provided")
		}

		if dohUrl != "" {
			r.req, err = requester.NewDoHRequester(dohUrl, domain, pubkey, utlsDistribution)
			if err != nil {
				return nil, err
			}
		}
		if dotAddr != "" {
			if r.req != nil {
				return nil, errors.New("only one of udpAddr, dohUrl, dotAddr may be provided")
			}
			r.req, err = requester.NewDoTRequester(dotAddr, domain, pubkey, utlsDistribution)
			if err != nil {
				return nil, err
			}
		}
	}
	if r.req == nil {
		return nil, errors.New("one of udpAddr, dohUrl, dotAddr must be provided")
	}

	r.ip, err = getPublicIp()
	if err != nil {
		Logger().Errorf("Failed to get public IP: [%v]", err)
		return nil, err
	}
	return r, nil
}

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

	Logger().Debugf("Payload length: [%d]", len(payload))

	for i := 0; i < r.maxTries; i++ {
		dnsResp := &pb.DnsResponse{}
		response, err := r.req.RequestAndRecv(payload)
		if err != nil {
			Logger().Warnf("error in sending request to DNS registrar: %v", err)
			continue
		}
		err = proto.Unmarshal(response, dnsResp)
		if err != nil {
			Logger().Warnf("error in storing Registrtion Response protobuf: %v", err)
			continue
		}
		if !dnsResp.GetSuccess() {
			Logger().Warnf("Registrar indicates that registration failed")
			continue
		}
		Logger().Debugf("%v DNS registration succeeded", cjSession.IDString())
		sleepWithContext(ctx, 2*time.Second)

		if !r.bidirectional {
			return reg, nil
		}
		if dnsResp.GetClientconfOutdated() {
			Logger().Warnf("Registrar indicates that ClinetConf is outdated")
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

func getPublicIp() ([]byte, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return nil, err
	}

	ipBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(string(ipBuf))

	if ip == nil {
		return nil, errors.New("ip parsing failed: [" + string(ipBuf) + "]")
	}

	Logger().Debugf("Public IP is: [%s]", ip.String())

	return ip.To4(), nil
}
