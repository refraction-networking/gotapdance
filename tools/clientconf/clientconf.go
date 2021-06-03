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

func printClientConf(clientConf *pb.ClientConf) {
	fmt.Printf("Generation: %d\n", clientConf.GetGeneration())
	if clientConf.GetDefaultPubkey() != nil {
		fmt.Printf("Default Pubkey: %s\n", hex.EncodeToString(clientConf.GetDefaultPubkey().Key[:]))
	}
	if clientConf.GetConjurePubkey() != nil {
		fmt.Printf("Conjure Pubkey: %s\n", hex.EncodeToString(clientConf.GetConjurePubkey().Key[:]))
	}
	if clientConf.DecoyList == nil {
		return
	}
	decoys := clientConf.DecoyList.TlsDecoys
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

	phantoms := clientConf.GetPhantomSubnetsList()
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
}

func parseClientConf(fname string) *pb.ClientConf {

	clientConf := &pb.ClientConf{}
	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}
	err = proto.Unmarshal(buf, clientConf)
	if err != nil {
		log.Fatal("Error parsing ClientConf", err)
	}
	return clientConf
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

func addSubnets(subnets []string, weight *uint, clientConf *pb.ClientConf) {
	if *weight == 0 {
		log.Fatal("Error: -add-subnet requires the weight flag to be set to a non-zero 32-bit unsinged integer")
	}
	for _, s := range subnets {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			log.Fatal("Error: " + s + " is not a valid CIDR block")
		}
	}
	var weight32 = uint32(*weight)
	
	// add new item to PhantomSubnetsList.WeightedSubnets
	var newPhantomSubnet = pb.PhantomSubnets{
		Weight:  &weight32,
		Subnets: subnets,
	}
	clientConf.PhantomSubnetsList.WeightedSubnets = append(clientConf.PhantomSubnetsList.WeightedSubnets, &newPhantomSubnet)
}

func deleteSubnet(index int, clientConf *pb.ClientConf) {
	if index < 0 {
		log.Fatal("Error: -delete-subnet requires a positive index")
	}
	var blockRange int = 0
	var weightedSubnets = &clientConf.PhantomSubnetsList.WeightedSubnets
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

func main() {
	var fname = flag.String("f", "", "`ClientConf` file to parse")
	var out_fname = flag.String("o", "", "`output` file name to write new/modified config")
	var generation = flag.Int("generation", 0, "New/modified generation")
	var pubkey = flag.String("pubkey", "", "New/modified (decoy) pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var cjPubkey = flag.String("cjpubkey", "", "New/modified (decoy) conjure pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var delpubkey = flag.Bool("delpubkey", false, "Delete pubkey from decoy with index specified in -update (or from all decoys if -all)")

	var add = flag.Bool("add", false, "If set, modify fields of all decoys in list with provided pubkey/timeout/tcpwin/host/ip")
	var delete = flag.Int("delete", -1, "Specifies `index` of decoy to delete")
	var update = flag.Int("update", -1, "Specifies `index` of decoy to update")

	var host = flag.String("host", "", "New/modified decoy host")
	var ip = flag.String("ip", "", "New/modified IP address")
	var timeout = flag.Int("timeout", 0, "New/modified timeout")
	var tcpwin = flag.Int("tcpwin", 0, "New/modified tcpwin")

	var add_subnets = flag.String("add-subnets", "", "Add a subnet or list of space-separated subnets between double quotes (\"127.0.0.1/24 2001::/32\" etc.), requires additional weight flag")
	var delete_subnet = flag.Int("delete-subnet", -1, "Specifies the index of a subnet to delete")
	var weight = flag.Uint("weight", 0, "Subnet weight when add-subnets is used")
	var subnet_file = flag.String("subnet-file", "", "Path to TOML file containing lists of subnets to use in config. TOML should be formatted like: \n"+
		"[[WeightedSubnets]] \n\tWeight = 9 \n\tSubnets = [\"192.122.190.0/24\", \"2001:48a8:687f:1::/64\"] \n"+
		"[[WeightedSubnets]] \n\tWeight = 1 \n\tSubnets = [\"141.219.0.0/16\", \"35.8.0.0/16\"]",
	)
	var all = flag.Bool("all", false, "If set, replace all pubkeys/timeouts/tcpwins in decoy list with pubkey/timeout/tcpwin if provided")

	var noout = flag.Bool("noout", false, "Don't print ClientConf")
	flag.Parse()

	clientConf := &pb.ClientConf{}

	// Parse ClientConf
	if *fname != "" {
		clientConf = parseClientConf(*fname)
	}

	// Use subnet-fille
	if *subnet_file != "" {
		tree, err := toml.LoadFile(*subnet_file)
		if err != nil {
			log.Fatalf("error opening configuration file: %v", err)
		}
		subnets := pb.PhantomSubnetsList{}
		tree.Unmarshal(&subnets)
		//fmt.Printf("%+v\n", subnets)
		clientConf.PhantomSubnetsList = &subnets
	}

	// Delete a subnet
	if *delete_subnet != -1 {
		deleteSubnet(*delete_subnet, clientConf)
	}
	// Add a subnet
	if *add_subnets != "" {
		subnets := strings.Split(*add_subnets, " ")
		addSubnets(subnets, weight, clientConf)
	}

	// Update generation
	if *generation != 0 {
		gen := uint32(*generation)
		clientConf.Generation = &gen
	}

	// Update pubkey
	if *pubkey != "" {
		if *add || *update != -1 {
			// Skip. -add or -delete will use pubkey

		} else {
			// Update default public key
			if clientConf.DefaultPubkey == nil {
				k := pb.PubKey{}
				key_type := pb.KeyType_AES_GCM_128
				k.Type = &key_type
				clientConf.DefaultPubkey = &k
			}
			clientConf.DefaultPubkey.Key = parsePubkey(*pubkey)
		}
	}

	// Update Conjure Pubkey.
	if *cjPubkey != "" {
		if *add || *update != -1 {
			// Skip. -add or -delete will use pubkey

		} else {
			// Update default public key
			if clientConf.ConjurePubkey == nil {
				k := pb.PubKey{}
				key_type := pb.KeyType_AES_GCM_128
				k.Type = &key_type
				clientConf.ConjurePubkey = &k
			}
			clientConf.ConjurePubkey.Key = parsePubkey(*cjPubkey)
		}
	}

	// Update all decoys
	if *all {
		for _, decoy := range clientConf.DecoyList.TlsDecoys {
			updateDecoy(decoy, *host, *ip, *pubkey, *delpubkey, *timeout, *tcpwin)
		}
	}

	// Update a single decoy from the list
	if *update != -1 {
		decoy := clientConf.DecoyList.TlsDecoys[*update]
		updateDecoy(decoy, *host, *ip, *pubkey, *delpubkey, *timeout, *tcpwin)
	}

	// Delete a decoy
	if *delete != -1 {
		idx := *delete
		decoys := clientConf.DecoyList.TlsDecoys
		clientConf.DecoyList.TlsDecoys = append(decoys[:idx], decoys[idx+1:]...)
	}

	// Add a decoy
	if *add {
		if *host == "" || *ip == "" {
			log.Fatal("Error: -add requires -host and -ip")
		}
		if *update != -1 {
			log.Fatal("Error: -add cannot be used with -update")
		}

		decoy := pb.TLSDecoySpec{}
		updateDecoy(&decoy, *host, *ip, *pubkey, *delpubkey, *timeout, *tcpwin)

		if clientConf.DecoyList == nil {
			tls_spec := pb.DecoyList{}
			clientConf.DecoyList = &tls_spec
		}
		clientConf.DecoyList.TlsDecoys = append(clientConf.DecoyList.TlsDecoys, &decoy)
	}

	if !*noout {
		printClientConf(clientConf)
	}

	if *out_fname != "" {
		buf, err := proto.Marshal(clientConf)
		if err != nil {
			log.Fatal("Error writing output:", err)
		}
		err = ioutil.WriteFile(*out_fname, buf[:], 0644)
		if err != nil {
			log.Fatal("Error writing output:", err)
		}
	}
}
