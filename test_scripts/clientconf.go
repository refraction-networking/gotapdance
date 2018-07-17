package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"io/ioutil"
	"log"
	"net"
)

func printClientConf(clientConf pb.ClientConf) {
	fmt.Printf("Generation: %d\n", clientConf.GetGeneration())
	fmt.Printf("Default Pubkey: %s\n", hex.EncodeToString(clientConf.GetDefaultPubkey().Key[:]))
	decoys := clientConf.DecoyList.TlsDecoys
	fmt.Printf("Decoy List: %d decoys\n", len(decoys))
	for i, decoy := range decoys {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, decoy.GetIpv4Addr())
		fmt.Printf("%d:\n  %s (%s)\n", i, decoy.GetHostname(), ip.To4().String())
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

func parseClientConf(fname string) pb.ClientConf {

	clientConf := pb.ClientConf{}
	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}
	err = proto.Unmarshal(buf, &clientConf)
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
		ip4 := binary.BigEndian.Uint32(net.ParseIP(ip).To4())
		decoy.Ipv4Addr = &ip4
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

func main() {
	var fname = flag.String("f", "", "`ClientConf` file to parse")
	var out_fname = flag.String("o", "", "`output` file name to write new/modified config")
	var generation = flag.Int("generation", 0, "New/modified generation")
	var pubkey = flag.String("pubkey", "", "New/modified (decoy) pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var delpubkey = flag.Bool("delpubkey", false, "Delete pubkey from decoy (or all if -all)")

	var add = flag.Bool("add", false, "Add a new decoy. Must set -host and -ip, optionally set -timeout, -tcpwin and -pubkey")
	var delete = flag.Int("delete", -1, "Delete a decoy at `index`")
	var update = flag.Int("update", -1, "Update a decoy at `index`")

	var host = flag.String("host", "", "New/modified decoy host")
	var ip = flag.String("ip", "", "New/modified IP address")
	var timeout = flag.Int("timeout", 0, "New/modified timeout")
	var tcpwin = flag.Int("tcpwin", 0, "New/modified tcpwin")

	var all = flag.Bool("all", false, "If set, replace all pubkeys/timeouts/tcpwins in decoy list with pubkey/timeout/tcpwin if provided")

	var noout = flag.Bool("noout", false, "Don't print ClientConf")
	flag.Parse()

	clientConf := pb.ClientConf{}

	// Parse ClientConf
	if *fname != "" {
		clientConf = parseClientConf(*fname)
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
			clientConf.DefaultPubkey.Key = parsePubkey(*pubkey)
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

		clientConf.DecoyList.TlsDecoys = append(clientConf.DecoyList.TlsDecoys, &decoy)
	}

	if !*noout {
		printClientConf(clientConf)
	}

	if *out_fname != "" {
		buf, err := proto.Marshal(&clientConf)
		if err != nil {
			log.Fatal("Error writing output:", err)
		}
		err = ioutil.WriteFile(*out_fname, buf[:], 0644)
		if err != nil {
			log.Fatal("Error writing output:", err)
		}
	}
}
