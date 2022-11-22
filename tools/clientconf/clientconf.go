package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
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
	if clientConf.DecoyList != nil {
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

// Single line, not nice for printing, but good for diffs
func decoyToStr(decoy pb.TLSDecoySpec) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, decoy.GetIpv4Addr())
	ip6 := net.IP(decoy.GetIpv6Addr())
	pk_s := ""
	if decoy.GetPubkey() != nil {
		pk_s = hex.EncodeToString(decoy.GetPubkey().Key[:])
	}

	return fmt.Sprintf("%s (%s / [%s]) pk: %s to: %d win: %d",
		decoy.GetHostname(), ip.To4().String(), ip6.To16().String(),
		pk_s, decoy.GetTimeout(), decoy.GetTcpwin())
}

func keyToStr(key *pb.PubKey) string {
	if key == nil {
		return ""
	}
	return hex.EncodeToString(key.Key[:])
}

func phantomsToMap(list *pb.PhantomSubnetsList) (map[string]uint, []string) {
	var index uint = 0
	out_map := make(map[string]uint)
	var out_list []string
	if list == nil {
		return out_map, out_list
	}
	for _, block := range list.GetWeightedSubnets() {
		for _, subnet := range block.GetSubnets() {
			subnet_str := fmt.Sprintf("weight: %d, %s", block.GetWeight(), subnet)
			out_map[subnet_str] = index
			out_list = append(out_list, subnet_str)
			index++
		}
	}
	return out_map, out_list
}

func printPairs(clientConf *pb.ClientConf) {

	ip := ""
	for _, decoy := range clientConf.DecoyList.TlsDecoys {
		decoy_ip4 := make(net.IP, 4)
		binary.BigEndian.PutUint32(decoy_ip4, decoy.GetIpv4Addr())
		decoy_ip6 := net.IP(decoy.GetIpv6Addr())
		if decoy_ip4.To4().String() != "0.0.0.0" {
			ip = decoy_ip4.To4().String()
		} else {
			ip = decoy_ip6.To16().String()
		}
		fmt.Printf("%s,%s\n", ip, decoy.GetHostname())
	}
}

func printDiff(old *pb.ClientConf, new_fn string) {

	new := parseClientConf(new_fn)

	if old.GetGeneration() != new.GetGeneration() {
		fmt.Printf("- Generation: %d\n", old.GetGeneration())
		fmt.Printf("+ Generation: %d\n", new.GetGeneration())
	}

	old_key := keyToStr(old.GetDefaultPubkey())
	new_key := keyToStr(new.GetDefaultPubkey())
	if old_key != new_key {
		if old_key != "" {
			fmt.Printf("- Default Pubkey: %s\n", old_key)
		}
		if new_key != "" {
			fmt.Printf("+ Default Pubkey: %s\n", new_key)
		}
	}

	old_cj_key := keyToStr(old.GetConjurePubkey())
	new_cj_key := keyToStr(new.GetConjurePubkey())
	if old_cj_key != new_cj_key {
		if old_cj_key != "" {
			fmt.Printf("- Conjure Pubkey: %s\n", old_cj_key)
		}
		if new_cj_key != "" {
			fmt.Printf("+ Conjure Pubkey: %s\n", new_cj_key)
		}
	}

	if old.DecoyList == nil {
		return
	}
	odecoys := old.DecoyList.TlsDecoys
	ndecoys := new.DecoyList.TlsDecoys

	fmt.Printf("Decoy List: %d -> %d decoys\n", len(odecoys), len(ndecoys))

	n := len(odecoys)
	if len(ndecoys) > n {
		n = len(ndecoys)
	}

	// Map of decoy => index in respective array
	old_decoys := make(map[string]int)
	new_decoys := make(map[string]int)

	all_decoys := make(map[string]int) // List of all decoys (union of both)

	for i := 0; i < n; i++ {
		od := pb.TLSDecoySpec{} // Old Decoy
		nd := pb.TLSDecoySpec{} // New Decoy
		if i < len(odecoys) {
			od = *odecoys[i]
			old_decoys[decoyToStr(od)] = i
			all_decoys[decoyToStr(od)] = 1
		}
		if i < len(ndecoys) {
			nd = *ndecoys[i]
			new_decoys[decoyToStr(nd)] = i
			all_decoys[decoyToStr(nd)] = 1
		}
	}

	// Since we don't really care about order, we don't need a fancy diff like Meyers
	// Just find the ones that are in old and not in new first
	removed_idxs := make(map[int]int) // indexes in odecoys
	added_idxs := make(map[int]int)   // indexes in ndecoys

	for k := range all_decoys {
		old_idx, in_old := old_decoys[k]
		new_idx, in_new := new_decoys[k]

		if in_old && in_new {
			// In both
		} else if in_old {
			removed_idxs[old_idx] = -1
		} else if in_new {
			added_idxs[new_idx] = -1
		}
	}

	for i := 0; i < len(all_decoys); i++ {
		_, del := removed_idxs[i]
		_, add := added_idxs[i]

		if del {
			fmt.Printf("- %d:  %s\n", i, decoyToStr(*odecoys[i]))
		}
		if add {
			fmt.Printf("+ %d:  %s\n", i, decoyToStr(*ndecoys[i]))
		}

		if !del && !add {
			//fmt.Printf("%d\n  %s\n", i, decoyToStr(*odecoys[i]))
		}
	}

	old_phantom_map, old_phantoms := phantomsToMap(old.GetPhantomSubnetsList())
	new_phantom_map, new_phantoms := phantomsToMap(new.GetPhantomSubnetsList())

	for i, phantom := range old_phantoms {
		_, in_new := new_phantom_map[phantom]
		if !in_new {
			fmt.Printf("- %d: %s\n", i, phantom)
		}
	}

	for i, phantom := range new_phantoms {
		_, in_old := old_phantom_map[phantom]
		if !in_old {
			fmt.Printf("+ %d: %s\n", i, phantom)
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
			fmt.Printf("index: %d, block_range: %d, len_block: %d\n", index, blockRange, len(block.Subnets))
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

func deleteStringSubnet(subnetStr string, clientConf *pb.ClientConf) error {

	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return err
	}

	remainingDecoys := []*pb.TLSDecoySpec{}
	for _, decoy := range clientConf.DecoyList.TlsDecoys {
		ip4 := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip4, decoy.GetIpv4Addr())

		ip6 := net.IP(decoy.GetIpv6Addr())

		if !(subnet.Contains(ip4) || subnet.Contains(ip6)) {
			remainingDecoys = append(remainingDecoys, decoy)
		}
	}

	clientConf.DecoyList.TlsDecoys = remainingDecoys

	return nil
}

func deleteStringPattern(pattern string, clientConf *pb.ClientConf) error {

	remainingDecoys := []*pb.TLSDecoySpec{}
	r, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	for _, decoy := range clientConf.DecoyList.TlsDecoys {
		if !r.MatchString(*decoy.Hostname) {
			remainingDecoys = append(remainingDecoys, decoy)
		}
	}

	clientConf.DecoyList.TlsDecoys = remainingDecoys

	return nil
}

func decoysToDeleteFromFile(filename string, clientConf *pb.ClientConf) error {

	f_read, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f_read.Close()
	var lines []string
	scanner := bufio.NewScanner(f_read)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	remainingDecoys := clientConf.DecoyList.TlsDecoys

	for idx, decoy := range clientConf.DecoyList.TlsDecoys {
		decoy_ip4 := make(net.IP, 4)
		binary.BigEndian.PutUint32(decoy_ip4, decoy.GetIpv4Addr())
		decoy_ip6 := net.IP(decoy.GetIpv6Addr())

		for _, line := range lines {
			pair := strings.Split(line, ",")
			ip := pair[0]
			sni := pair[1]
			if strings.Contains(ip, ":") {
				if ip == decoy_ip6.To16().String() && sni == decoy.GetHostname() {
					remainingDecoys = append(remainingDecoys[:idx], remainingDecoys[idx+1:]...)
				}
			} else {
				if ip == decoy_ip4.To16().String() && sni == decoy.GetHostname() {
					remainingDecoys = append(remainingDecoys[:idx], remainingDecoys[idx+1:]...)
				}
			}
		}
		clientConf.DecoyList.TlsDecoys = remainingDecoys
	}
	return nil
}


func main() {
	var fname = flag.String("f", "", "`ClientConf` file to parse")
	var out_fname = flag.String("o", "", "`output` file name to write new/modified config")
	var generation = flag.Int("generation", 0, "New/modified generation")
	var next_gen = flag.Bool("next-gen", false, "Assign the next generation number to the created ClientConf based on the provided one")
	var pubkey = flag.String("pubkey", "", "New/modified (decoy) pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var cjPubkey = flag.String("cjpubkey", "", "New/modified (decoy) conjure pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var delpubkey = flag.Bool("delpubkey", false, "Delete pubkey from decoy with index specified in -update (or from all decoys if -all)")

	var add = flag.Bool("add", false, "If set, modify fields of all decoys in list with provided pubkey/timeout/tcpwin/host/ip")
	var delete = flag.Int("delete", -1, "Specifies `index` of decoy to delete")
	var deleteStr = flag.String("delete-str", "", "Specifies pattern of decoy hostnames to delete")
	var deleteDecoysBySubnet = flag.String("delete-decoys-subnet", "", "Specifies subnet of decoy addresses to delete")
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
	var diff = flag.String("diff", "", "A second conf to diff against (-f old -diff new)")
	var rm_decoys = flag.String("rm-decoys", "", "File of decoys to delete from ClientConf.\n"+
		"Each line in the file has to be in the following format:\n"+
		"ip,sni\n",
	)
	var print_pairs = flag.Bool("print-pairs", false, "Print pairs of decoys ip,sni")

	flag.Parse()

	clientConf := &pb.ClientConf{}

	// Parse ClientConf
	if *fname != "" {
		clientConf = parseClientConf(*fname)
	}

	// Use subnet-file
	if *subnet_file != "" {

		data, err := ioutil.ReadFile(*subnet_file)
		if err != nil {
			log.Fatalf("error opening configuration file: %v", err)
		}
		subnets := pb.PhantomSubnetsList{}
		err = toml.Unmarshal(data, &subnets)
		if err != nil {
			log.Fatalf("error unmarshalling data into PhantomSubnetList structure %v", err)
		}
		clientConf.PhantomSubnetsList = &subnets
	}

	// Delete a subnet
	if *delete_subnet != -1 {
		deleteSubnet(*delete_subnet, clientConf)
	}

	// Deletes decoys based on pattern for decoy hostname
	if *deleteStr != "" {
		err := deleteStringPattern(*deleteStr, clientConf)
		if err != nil {
			log.Fatalf("failed string pattern decoy delete: %v", err)
		}
	}

	// Delete decoys based on subnet of decoy address
	if *deleteDecoysBySubnet != "" {
		err := deleteStringSubnet(*deleteDecoysBySubnet, clientConf)
		if err != nil {
			log.Fatalf("failed subnet based decoy delete: %v", err)
		}
	}

	// Delete decoys based on a given file path containing line(s) of "ip,sni" decoys
	if *rm_decoys != "" {
		err := decoysToDeleteFromFile(*rm_decoys, clientConf)
		if err != nil {
			log.Fatalf("failed file based decoy delete %v", err)
		}
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
	} else if *next_gen {
		gen := clientConf.GetGeneration()
		gen++
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
		if *diff != "" {
			printDiff(clientConf, *diff)
		} else {
			printClientConf(clientConf)
		}
	}

	// Print pairs of decoy addresses (ip,sni)
	if *print_pairs {
		printPairs(clientConf)
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
