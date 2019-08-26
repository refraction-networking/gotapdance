package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/golang/protobuf/proto"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
)

func main() {
	var fname = flag.String("f", "", "`ClientConf` file to parse")
	var out_fname = flag.String("o", "", "`output` file name to write new/modified config")

	var connect_to_all = flag.Bool("connect_to_all", false, "")
	var workers = flag.Uint("w", 20, "")

	var generation = flag.Int("generation", 0, "New/modified generation")
	var pubkey = flag.String("pubkey", "", "New/modified (decoy) pubkey. If -add or -update, applies to specific decoy. If -all applies to all decoys. Otherwise, applies to default pubkey.")
	var delpubkey = flag.Bool("delpubkey", false, "Delete pubkey from decoy with index specified in -update (or from all decoys if -all)")

	var add = flag.Bool("add", false, "If set, modify fields of all decoys in list with provided pubkey/timeout/tcpwin/host/ip")
	var delete = flag.Int("delete", -1, "Specifies `index` of decoy to delete")
	var update = flag.Int("update", -1, "Specifies `index` of decoy to update")

	var host = flag.String("host", "", "New/modified decoy host")
	var ip = flag.String("ip", "", "New/modified IP address")
	var timeout = flag.Int("timeout", 0, "New/modified timeout")
	var tcpwin = flag.Int("tcpwin", 0, "New/modified tcpwin")

	var all = flag.Bool("all", false, "If set, replace all pubkeys/timeouts/tcpwins in decoy list with pubkey/timeout/tcpwin if provided")

	var add_block = flag.String("add_block", "", "If set add new CIDR format IP block for Dark Decoy IP selection")
	var delete_block = flag.Int("delete_block", -1, "Specifies `index` of Dark Decoy IP block to delete")

	var noout = flag.Bool("noout", false, "Don't print ClientConf")
	flag.Parse()

	clientConf := pb.ClientConf{}

	// Parse ClientConf
	if *fname != "" {
		clientConf = parseClientConf(*fname)
	}

	if *connect_to_all {
		ConnectToAll(clientConf.DecoyList.GetTlsDecoys(), *workers)
		os.Exit(0)
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

	// Add CIDR Dark Decoy Block
	if *add_block != "" {
		_, _, err := net.ParseCIDR(*add_block)
		if err == nil {
			if clientConf.GetDarkDecoyBlocks() == nil {
				blocks := pb.DarkDecoyBlocks{}
				clientConf.DarkDecoyBlocks = &blocks
			}
			clientConf.DarkDecoyBlocks.Blocks = append(clientConf.DarkDecoyBlocks.Blocks, *add_block)
		} else {
			fmt.Printf("[Error] IP block not in proper CIDR notation: %s\n\n", *add_block)
		}
	}

	// Delete CIDR Dark Decoy Block
	if *delete_block != -1 {
		idx := *delete_block
		if clientConf.GetDarkDecoyBlocks() != nil {
			blocks := clientConf.DarkDecoyBlocks.Blocks
			if idx < len(blocks) {
				clientConf.DarkDecoyBlocks.Blocks = append(blocks[:idx], blocks[idx+1:]...)
			}
		}
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
