package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"github.com/golang/protobuf/proto"
	toml "github.com/pelletier/go-toml"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// Track all cmdline parameters in struct
type flagValues struct {
	fname, out_fname, pubkey, cjPubkey, host, ip, add_subnets, subnet_file, registrar_type, registrar_host, registrar_file          string
	generation, del_decoy, update_decoy, update_config, del_config, timeout, tcpwin, delete_subnet, update_registrar, del_registrar int
	delpubkey, add_decoy, add_config, all_decoys, add_registrar, reg_bidir, noout                                                   bool
	weight                                                                                                                          uint
}

func parseCmdLineFlags() *flagValues {
	var fname = flag.String("f", "", "`ClientConf2` file to parse")
	var out_fname = flag.String("o", "", "`output` file name to write new/modified config")
	var generation = flag.Int("generation", 0, "New/modified generation")
	var pubkey = flag.String("pubkey", "", "New/modified (decoy) pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var cjPubkey = flag.String("cjpubkey", "", "New/modified (decoy) conjure pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var delpubkey = flag.Bool("delpubkey", false, "Delete pubkey from decoy with `index` specified in -update (or from all decoys if -all)")

	var add_decoy = flag.Bool("add-decoy", false, "If set, modify fields of all decoys in list with provided pubkey/timeout/tcpwin/host/ip")
	var del_decoy = flag.Int("del-decoy", -1, "Specifies `index` of decoy to delete")
	var update_decoy = flag.Int("update-decoy", -1, "Specifies `index` of decoy to update")
	var update_config = flag.Int("update-config", -1, "Specifies `index` of deployment config to update")
	var add_config = flag.Bool("add-config", false, "If set, creates new decoy and appends to decoy list. Can 'initialize' values by setting -pubkey, -generation, etc. flags.")
	var del_config = flag.Int("del-config", -1, "Specifies `index` of deployment config to delete")

	var host = flag.String("host", "", "New/modified decoy host")
	var ip = flag.String("ip", "", "New/modified IP address")
	var timeout = flag.Int("timeout", 0, "New/modified timeout")
	var tcpwin = flag.Int("tcpwin", 0, "New/modified tcpwin")

	var add_subnets = flag.String("add-subnets", "", "Add a subnet or list of space-separated subnets between double quotes (\"127.0.0.1/24 2001::/32\" etc.), requires additional weight flag")
	var delete_subnet = flag.Int("delete-subnet", -1, "Specifies the `index` of a subnet to delete")
	var weight = flag.Uint("weight", 0, "Subnet weight when add-subnets is used")
	var subnet_file = flag.String("subnet-file", "", "Path to TOML file containing lists of subnets to use in config. TOML should be formatted like: \n"+
		"[[WeightedSubnets]] \n\tWeight = 9 \n\tSubnets = [\"192.122.190.0/24\", \"2001:48a8:687f:1::/64\"] \n"+
		"[[WeightedSubnets]] \n\tWeight = 1 \n\tSubnets = [\"141.219.0.0/16\", \"35.8.0.0/16\"]",
	)
	var all_decoys = flag.Bool("all-decoys", false, "If set, replace all pubkeys/timeouts/tcpwins in decoy list with pubkey/timeout/tcpwin if provided")

	var add_registrar = flag.Bool("add-registrar", false, "If set, adds a registrar, requires -registrar-type and -registrar-host")
	var update_registrar = flag.Int("update-registrar", -1, "Specifies `index` of registrar to update")
	var del_registrar = flag.Int("del-registrar", -1, "Specifies `index` of registrar to remove")
	var registrar_type = flag.String("registrar-type", "", "Set registrar type `<unknown | api | dns | decoy>`")
	var reg_bidir = flag.Bool("registrar-bidir", false, "Specifies whether registrar is bidirectional")
	var registrar_file = flag.String("registrar-file", "", "Path to TOML file containing DNS/API/Decoy parameters")

	var noout = flag.Bool("noout", false, "Don't print ClientConf")

	flag.Parse()

	return &flagValues{
		fname:            *fname,
		out_fname:        *out_fname,
		pubkey:           *pubkey,
		cjPubkey:         *cjPubkey,
		host:             *host,
		ip:               *ip,
		add_subnets:      *add_subnets,
		subnet_file:      *subnet_file,
		generation:       *generation,
		del_decoy:        *del_decoy,
		update_decoy:     *update_decoy,
		update_config:    *update_config,
		add_config:       *add_config,
		del_config:       *del_config,
		timeout:          *timeout,
		tcpwin:           *tcpwin,
		delete_subnet:    *delete_subnet,
		delpubkey:        *delpubkey,
		add_decoy:        *add_decoy,
		all_decoys:       *all_decoys,
		noout:            *noout,
		weight:           *weight,
		add_registrar:    *add_registrar,
		update_registrar: *update_registrar,
		del_registrar:    *del_registrar,
		registrar_type:   *registrar_type,
		reg_bidir:        *reg_bidir,
		registrar_file:   *registrar_file,
	}
}

func printClientConf(clientConf *pb.ClientConfig2) {
	// ClientConfig2 wrapper info
	fmt.Println("ClientConfig2")
	fmt.Println("Version number:", clientConf.GetVersionNumber())
	for i, conf := range clientConf.DeploymentConfigs {
		fmt.Println()
		decoyHeader := fmt.Sprintf("Deployment Config %d", i)
		fmt.Println(decoyHeader)
		fmt.Println(strings.Repeat("=", 80)) // 80 = std terminal width
		fmt.Println()
		printDeployConf(conf)
	}
}

func printDeployConf(deployConf *pb.DeploymentConfig) {
	fmt.Printf("Generation: %d\n", deployConf.GetGeneration())
	if deployConf.GetDefaultPubkey() != nil {
		fmt.Printf("Default Pubkey: %s\n", hex.EncodeToString(deployConf.GetDefaultPubkey().Key[:]))
	}
	if deployConf.GetConjurePubkey() != nil {
		fmt.Printf("Conjure Pubkey: %s\n", hex.EncodeToString(deployConf.GetConjurePubkey().Key[:]))
	}
	if deployConf.DecoyList == nil {
		return
	}
	decoys := deployConf.DecoyList.TlsDecoys
	fmt.Printf("Decoy List: %d decoys\n", len(decoys))
	for i, decoy := range decoys {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, decoy.GetIpv4Addr())
		ip6 := net.IP(decoy.GetIpv6Addr())
		fmt.Printf("%d:\n  %s (%s / [%s])\n", i, decoy.GetHostname(), ip.To4().String(), ip6.To16().String())
		if decoy.GetPubkey() != nil {
			fmt.Printf("  pubkey: %s\n", hex.EncodeToString(decoy.GetPubkey().Key[:]))
		}
		if decoy.GetTimeout() != 0 {
			fmt.Printf("  timeout: %d ms\n", decoy.GetTimeout())
		}
		if decoy.GetTcpwin() != 0 {
			fmt.Printf("  tcpwin: %d bytes\n", decoy.GetTcpwin())
		}
	}

	phantoms := deployConf.GetPhantomSubnetsList()
	if phantoms != nil {
		fmt.Printf("\nPhantom Subnets List:\n")
		var index uint = 0
		for _, block := range phantoms.GetWeightedSubnets() {
			fmt.Printf("\nweight: %d, subnets:\n", block.GetWeight())
			for _, subnet := range block.GetSubnets() {
				fmt.Printf(" %d: %s\n", index, subnet)
				index++
			}
		}
	}

	registrars := deployConf.GetRegistrars()
	if registrars != nil {
		fmt.Printf("\nRegistrars:\n")
		for i, reg := range registrars {
			fmt.Printf("%d:\n", i)
			fmt.Printf("  Bidirectional: %t\n", reg.GetBidirectional())

			var reg_type string
			switch reg.GetRegistrarType() {
			case pb.RegistrarType_REGISTRAR_TYPE_UNKNOWN:
				reg_type = "unknown"
			case pb.RegistrarType_REGISTRAR_TYPE_API:
				reg_type = "api"
			case pb.RegistrarType_REGISTRAR_TYPE_DECOY:
				reg_type = "decoy"
			case pb.RegistrarType_REGISTRAR_TYPE_DNS:
				reg_type = "dns"
			default:
				log.Fatalf("unknown DNS protocol type %s", reg_type)
			}
			fmt.Printf("  Type: %s\n", reg_type)

			api_params := reg.GetApiRegConfParams()
			if api_params != nil && api_params.GetApiUrl() != "" {
				fmt.Printf("  %s params:\n", reg_type)
				fmt.Printf("    API URL: %s\n", api_params.GetApiUrl())
			}

			// Decoy message empty, nothing to do
			//decoy_params := reg.GetDecoyRegConfParams()
			//if decoy_params != nil {
			//	// pass
			//}

			dns_params := reg.GetDnsRegConfParams()
			if dns_params != nil {
				fmt.Printf("  %s params:\n", reg_type)
				var dns_reg_method string
				switch dns_params.GetDnsRegMethod() {
				case pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UNKNOWN:
					dns_reg_method = "unknown"
				case pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UDP:
					dns_reg_method = "udp"
				case pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_DOH:
					dns_reg_method = "doh"
				case pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_DOT:
					dns_reg_method = "dot"
				}
				fmt.Printf("    DnsRegMethod: %s\n", dns_reg_method)
				if dns_params.GetUdpAddr() != "" {
					fmt.Printf("    UDP Addr: %s\n", dns_params.GetUdpAddr())
				}
				if dns_params.GetDotAddr() != "" {
					fmt.Printf("    DoT Addr: %s\n", dns_params.GetDotAddr())
				}
				if dns_params.GetDohUrl() != "" {
					fmt.Printf("    DoH URL: %s\n", dns_params.GetDohUrl())
				}
				fmt.Printf("    Domain: %s\n", dns_params.GetDomain())
				fmt.Printf("    Pubkey: %s\n", hex.EncodeToString(dns_params.GetPubkey()))
				if dns_params.GetUtlsDistribution() != "" {
					fmt.Printf("    Utls Distribution: %s\n", dns_params.GetUtlsDistribution())
				}
				if dns_params.GetStunServer() != "" {
					fmt.Printf("    STUN Server: %s\n", dns_params.GetStunServer())
				}
			}

			decoy_params := reg.GetDecoyRegConfParams()
			if decoy_params != nil {
				// pass
			}
		}
	}
}

func parseClientConf(fname string) *pb.ClientConfig2 {
	clientConf := &pb.ClientConfig2{}
	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}

	err = proto.Unmarshal(buf, clientConf)
	if err != nil {
		log.Fatal("Error parsing ClientConfig2", err)
	}

	return clientConf
}

func updateDeployConf(deployConf *pb.DeploymentConfig, params *flagValues) {
	// Use subnet-file
	if params.subnet_file != "" {
		tree, err := toml.LoadFile(params.subnet_file)
		if err != nil {
			log.Fatalf("error opening configuration file: %v", err)
		}
		subnets := pb.PhantomSubnetsList{}
		tree.Unmarshal(&subnets)
		deployConf.PhantomSubnetsList = &subnets
	}

	// Delete a subnet
	if params.delete_subnet != -1 {
		deleteSubnet(params.delete_subnet, deployConf)
	}

	// Add a subnet
	if params.add_subnets != "" {
		subnets := strings.Split(params.add_subnets, " ")
		addSubnets(subnets, params.weight, deployConf)
	}

	// Update generation
	if params.generation != 0 {
		gen := uint32(params.generation)
		deployConf.Generation = &gen
	}

	// Update pubkey
	if params.pubkey != "" {
		if params.add_decoy || params.update_decoy != -1 {
			// Skip. -add-decoy or -delete will use pubkey

		} else {
			// Update default public key
			if deployConf.DefaultPubkey == nil {
				k := pb.PubKey{}
				key_type := pb.KeyType_AES_GCM_128
				k.Type = &key_type
				deployConf.DefaultPubkey = &k
			}
			deployConf.DefaultPubkey.Key = parsePubkey(params.pubkey)
		}
	}

	// Update Conjure Pubkey.
	if params.cjPubkey != "" {
		if params.add_decoy || params.update_decoy != -1 {
			// Skip. -add or -delete will use pubkey

		} else {
			// Update default public key
			if deployConf.ConjurePubkey == nil {
				k := pb.PubKey{}
				key_type := pb.KeyType_AES_GCM_128
				k.Type = &key_type
				deployConf.ConjurePubkey = &k
			}
			deployConf.ConjurePubkey.Key = parsePubkey(params.cjPubkey)
		}
	}

	// Update registrar
	if params.update_registrar != -1 {
		if params.update_registrar < 0 || params.update_registrar >= len(deployConf.GetRegistrars()) {
			log.Fatalf("Error: Index %d provided to -update-registrar is out of range", params.update_registrar)
		} else if params.registrar_host == "" || params.registrar_type == "" {
			log.Fatalf("Error: -update-registrar requires -registrar-host and -registrar-type")
		}
		// TODO
	}

	// Delete registrar
	if params.del_registrar != -1 {
		if params.del_registrar >= len(deployConf.GetRegistrars()) {
			log.Fatalf("Error: Index %d provided to -del-registrar is out of range", params.del_registrar)
		}
		// TODO
	}

	// Add registrar
	if params.add_registrar {
		var reg_type_val pb.RegistrarType
		switch strings.ToLower(params.registrar_type) {
		case "unknown":
			reg_type_val = pb.RegistrarType_REGISTRAR_TYPE_UNKNOWN
		case "api":
			reg_type_val = pb.RegistrarType_REGISTRAR_TYPE_API
		case "decoy":
			reg_type_val = pb.RegistrarType_REGISTRAR_TYPE_DECOY
		case "dns":
			reg_type_val = pb.RegistrarType_REGISTRAR_TYPE_DNS
		default:
			log.Fatalf("error: invalid/empty input %s passed to -registrar-type", params.registrar_type)
		}
		new_reg := &pb.Registrar{
			RegistrarType: &reg_type_val,
			Bidirectional: &params.reg_bidir,
		}
		if params.registrar_file != "" {
			parseRegistrarConf(params.registrar_file, new_reg)
		}
		deployConf.Registrars = append(deployConf.Registrars, new_reg)
	}

	// Update all decoys
	if params.all_decoys {
		for _, decoy := range deployConf.DecoyList.TlsDecoys {
			updateDecoy(decoy, params.host, params.ip, params.pubkey, params.delpubkey, params.timeout, params.tcpwin)
		}
	}

	// Update a single decoy from the list
	if params.update_decoy != -1 {
		decoy := deployConf.DecoyList.TlsDecoys[params.update_decoy]
		updateDecoy(decoy, params.host, params.ip, params.pubkey, params.delpubkey, params.timeout, params.tcpwin)
	}

	// Delete a decoy
	if params.del_decoy != -1 {
		idx := params.del_decoy
		decoys := deployConf.DecoyList.TlsDecoys
		deployConf.DecoyList.TlsDecoys = append(decoys[:idx], decoys[idx+1:]...)
	}

	// Add a decoy
	if params.add_decoy {
		if params.host == "" || params.ip == "" {
			log.Fatal("Error: -add-decoy requires -host and -ip")
		}
		if params.update_decoy != -1 {
			log.Fatal("Error: -add-decoy cannot be used with -update-decoy")
		}

		decoy := pb.TLSDecoySpec{}
		updateDecoy(&decoy, params.host, params.ip, params.pubkey, params.delpubkey, params.timeout, params.tcpwin)

		if deployConf.DecoyList == nil {
			tls_spec := pb.DecoyList{}
			deployConf.DecoyList = &tls_spec
		}
		deployConf.DecoyList.TlsDecoys = append(deployConf.DecoyList.TlsDecoys, &decoy)
	}
}

func parsePubkey(pubkey string) []byte {
	pubkey_bin, err := hex.DecodeString(pubkey)
	if err != nil {
		log.Fatal("Error parsing pubkey:", err)
	}
	if len(pubkey_bin) != 32 {
		log.Fatal("Error: pubkey length: expected 32, got ", len(pubkey_bin))
	}
	return pubkey_bin
}

func updateDecoy(decoy *pb.TLSDecoySpec, host string, ip string, pubkey string, delpubkey bool, timeout int, tcpwin int) {

	if host != "" {
		decoy.Hostname = &host
	}
	if ip != "" {
		ip4 := net.ParseIP(ip).To4()
		if ip4 != nil {
			uintIp4 := binary.BigEndian.Uint32(ip4)
			decoy.Ipv4Addr = &uintIp4
		} else {
			ip6 := net.ParseIP(ip).To16()
			fmt.Printf("%v", ip6.String())
			decoy.Ipv6Addr = []byte(ip6)
		}
	}
	if pubkey != "" {
		if decoy.Pubkey == nil {
			decoy.Pubkey = &pb.PubKey{}
		}
		decoy.Pubkey.Key = parsePubkey(pubkey)
	}
	if delpubkey {
		decoy.Pubkey = nil
	}
	if timeout != 0 {
		t := uint32(timeout)
		decoy.Timeout = &t
	}
	if tcpwin != 0 {
		t := uint32(tcpwin)
		decoy.Tcpwin = &t
	}

}

func addSubnets(subnets []string, weight uint, deployConf *pb.DeploymentConfig) {
	if weight == 0 {
		log.Fatal("Error: -add-subnets requires the weight flag to be set to a non-zero 32-bit unsinged integer")
	}
	for _, s := range subnets {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			log.Fatal("Error: " + s + " is not a valid CIDR block")
		}
	}
	var weight32 = uint32(weight)

	// add new item to PhantomSubnetsList.WeightedSubnets
	var newPhantomSubnet = pb.PhantomSubnets{
		Weight:  &weight32,
		Subnets: subnets,
	}
	if deployConf.PhantomSubnetsList == nil {
		deployConf.PhantomSubnetsList = &pb.PhantomSubnetsList{}
	}
	deployConf.PhantomSubnetsList.WeightedSubnets = append(deployConf.PhantomSubnetsList.WeightedSubnets, &newPhantomSubnet)
}

func deleteSubnet(index int, deployConf *pb.DeploymentConfig) {
	if index < 0 {
		log.Fatal("Error: -delete-subnet requires a positive index")
	}
	var blockRange int = 0
	var weightedSubnets = &deployConf.PhantomSubnetsList.WeightedSubnets
	for blockIndex, block := range *weightedSubnets {
		blockRange += len(block.Subnets)
		if blockRange > index {
			fmt.Printf("index: %d, block_range: %d, len_block: %d", index, blockRange, len(block.Subnets))
			var indexInBlock = index - (blockRange - len(block.Subnets))
			block.Subnets[indexInBlock] = block.Subnets[len(block.Subnets)-1]
			block.Subnets = block.Subnets[:len(block.Subnets)-1]
			if len(block.Subnets) == 0 { // delete group if no longer contains subnets
				(*weightedSubnets)[blockIndex] = (*weightedSubnets)[len(*weightedSubnets)-1]
				(*weightedSubnets)[len(*weightedSubnets)-1] = nil
				*weightedSubnets = (*weightedSubnets)[:len(*weightedSubnets)-1]
			}
			return
		}
	}
	log.Fatal("Error: Index " + fmt.Sprint(index) + " provided to -delete-subnet is out of range")
}

func parseRegistrarConf(file string, reg *pb.Registrar) {
	tree, err := toml.LoadFile(file)
	if err != nil {
		log.Fatalf("error opening configuration file: %v", err.Error())
	}

	switch reg.GetRegistrarType() {
	case pb.RegistrarType_REGISTRAR_TYPE_UNKNOWN:
		// pass
	case pb.RegistrarType_REGISTRAR_TYPE_API:
		setRegParamsApi(reg, tree)
	case pb.RegistrarType_REGISTRAR_TYPE_DECOY:
		setRegParamsDecoy(reg, tree)
	case pb.RegistrarType_REGISTRAR_TYPE_DNS:
		setRegParamsDns(reg, tree)
	default:
		log.Fatalf("unknown registrar type: %s", reg.GetRegistrarType())
	}
}

func setRegParamsApi(reg *pb.Registrar, tree *toml.Tree) {
	api_params := &pb.APIRegConf{}
	err := tree.Unmarshal(api_params)
	if err != nil {
		log.Fatalf("error unmarshalling tree: %v", err)
	}
	reg.ApiRegConfParams = api_params
}

func setRegParamsDecoy(reg *pb.Registrar, tree *toml.Tree) {
	decoy_params := &pb.DecoyRegConf{}
	err := tree.Unmarshal(decoy_params)
	if err != nil {
		log.Fatalf("error unmarshalling tree: %v", err)
	}
	reg.DecoyRegConfParams = decoy_params
}

func setRegParamsDns(reg *pb.Registrar, tree *toml.Tree) {
	// Assert required fields (required in proto)
	if !tree.Has("DnsRegMethod") || !tree.Has("Domain") || !tree.Has("Pubkey") {
		log.Fatalf("DNSRegConf requires DnsRegMethod, Domain, and Pubkey")
	}

	// Convert fields with diff type than proto
	if tree.Has("DnsRegMethod") {
		dns_method_str := strings.ToLower(tree.Get("DnsRegMethod").(string))
		switch dns_method_str {
		case "unknown":
			tree.Set("DnsRegMethod", pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UNKNOWN)
		case "udp":
			tree.Set("DnsRegMethod", pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UDP)
		case "doh":
			tree.Set("DnsRegMethod", pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_DOH)
		case "dot":
			tree.Set("DnsRegMethod", pb.RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_DOT)
		default:
			log.Fatalf("unknown DNS protocol type %s", dns_method_str)
		}
	}

	if tree.Has("Pubkey") {
		pubkey_str := tree.Get("Pubkey").(string)
		tree.Set("Pubkey", parsePubkey(pubkey_str))
	}

	dns_params := &pb.DNSRegConf{}
	err := tree.Unmarshal(dns_params)
	if err != nil {
		log.Fatalf("error unmarshalling tree: %v", err)
	}
	reg.DnsRegConfParams = dns_params
}

func main() {
	params := parseCmdLineFlags()
	clientConf := &pb.ClientConfig2{}
	deployConf := &pb.DeploymentConfig{}

	// Parse ClientConf
	if params.fname != "" {
		clientConf = parseClientConf(params.fname)
	}

	// -add_config and -del_config cannot both be set
	if params.add_config && params.del_config != -1 {
		log.Fatal("Error: -add_config cannot be used with -del-config")
	}

	// Update deploy config
	if params.update_config != -1 {
		// Check whether index is valid
		if params.update_config < 0 || params.update_config >= len(clientConf.DeploymentConfigs) {
			log.Fatalf("Error: -update-config %d out of range, expected [0, %d)", params.update_config, len(clientConf.DeploymentConfigs))
		}

		// Select deploy conf and update
		deployConf = clientConf.DeploymentConfigs[params.update_config]
		updateDeployConf(deployConf, params)
	}

	// Delete deploy config
	if params.del_config != -1 {
		// Check whether index is valid
		if params.del_config < 0 || params.del_config >= len(clientConf.DeploymentConfigs) {
			log.Fatalf("Error: -del_config %d out of range, expected [0, %d)", params.del_config, len(clientConf.DeploymentConfigs))
		}

		clientConf.DeploymentConfigs = append(clientConf.DeploymentConfigs[:params.del_config], clientConf.DeploymentConfigs[params.del_config+1:]...)
	}

	// Append new deploy config
	if params.add_config {
		updateDeployConf(deployConf, params)
		clientConf.DeploymentConfigs = append(clientConf.GetDeploymentConfigs(), deployConf)
	}

	// Print all deploy configs
	if !params.noout {
		printClientConf(clientConf)
	}

	if params.out_fname != "" {
		buf, err := proto.Marshal(clientConf)
		if err != nil {
			log.Fatal("Error writing output:", err)
		}
		err = ioutil.WriteFile(params.out_fname, buf[:], 0644)
		if err != nil {
			log.Fatal("Error writing output:", err)
		}
	}
}
