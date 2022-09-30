package main

import (
	"fmt"
	"testing"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestRegParseDns(t *testing.T) {
	reg_type_const := pb.RegistrarType_REGISTRAR_TYPE_DNS
	true_var := true
	reg_dns := &pb.Registrar{
		RegistrarType: &reg_type_const,
		Bidirectional: &true_var,
	}
	parseRegistrarConf("reg_toml_examples/reg_dns_ex.toml", reg_dns)
	dns_params := reg_dns.GetDnsRegConfParams()

	dns_reg_method := dns_params.GetDnsRegMethod()
	dns_reg_method_exp := pb.RegistrarDNSProtocol(pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UDP)
	assert_eq("DnsRegMethod", dns_reg_method_exp, dns_reg_method, t)

	udp_addr := dns_params.GetUdpAddr()
	udp_addr_exp := "192.168.1.2"
	assert_eq("UdpAddr", udp_addr_exp, udp_addr, t)

	domain := dns_params.GetDomain()
	domain_exp := "cooldomainna.me"
	assert_eq("Domain", domain_exp, domain, t)

	pubkey := dns_params.GetPubkey()
	pubkey_exp := parsePubkey("103ebf3d7d501aa202c78b7016ffccd51079c4c00137500100ef5bd1cac47e16")
	assert_eq("Pubkey_len", len(pubkey_exp), len(pubkey), t)
	for i := range pubkey {
		assert_eq(fmt.Sprintf("Pubkey[%d]", i), pubkey_exp[i], pubkey[i], t)
	}

	utls_dist := dns_params.GetUtlsDistribution()
	utls_dist_exp := "utls"
	assert_eq("UtlsDistribution", utls_dist_exp, utls_dist, t)

	stun := dns_params.GetStunServer()
	stun_exp := "stun"
	assert_eq("StunServer", stun_exp, stun, t)
}

func TestRegParseApi(t *testing.T) {
	reg_type_const := pb.RegistrarType_REGISTRAR_TYPE_API
	false_var := false
	reg_api := &pb.Registrar{
		RegistrarType: &reg_type_const,
		Bidirectional: &false_var,
	}
	parseRegistrarConf("reg_toml_examples/reg_api_ex.toml", reg_api)
	api_params := reg_api.GetApiRegConfParams()

	api_url := api_params.GetApiUrl()
	api_url_exp := "apiurl.com"
	assert_eq("ApiUrl", api_url_exp, api_url, t)
}

func assert_eq(name string, exp, act interface{}, t *testing.T) {
	if exp != act {
		t.Fatal(name, ": expected", exp, ", got", act)
	}
}
