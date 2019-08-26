package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func printClientConf(clientConf pb.ClientConf) {
	fmt.Printf("Generation: %d\n", clientConf.GetGeneration())
	if clientConf.GetDefaultPubkey() != nil {
		fmt.Printf("\nDefault Pubkey: %s\n", hex.EncodeToString(clientConf.GetDefaultPubkey().Key[:]))
	}
	if clientConf.DecoyList == nil {
		return
	}
	decoys := clientConf.DecoyList.TlsDecoys
	fmt.Printf("\nDecoy List: %d decoys\n", len(decoys))
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
	if clientConf.GetDarkDecoyBlocks() != nil {
		darkDecoyBlocks := clientConf.DarkDecoyBlocks.Blocks
		fmt.Printf("\nDark Decoy Blocks: %d blocks\n", len(darkDecoyBlocks))
		for i, block := range darkDecoyBlocks {
			fmt.Printf("%d:\n  %s\n", i, block)
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

type jobTuple struct {
	Decoy *pb.TLSDecoySpec
	Total uint
	JobId uint
}

func ConnectToAll(decoyList []*pb.TLSDecoySpec, workers uint) {

	fmt.Println("Connection to all registration decoys in client conf.")

	decoyChan := make(chan jobTuple)

	for j := uint(1); j <= workers; j++ {
		go ConnectWorker(j, decoyChan)
	}

	for idx := 0; idx < len(decoyList); idx++ {
		decoyChan <- jobTuple{Decoy: decoyList[idx], Total: uint(len(decoyList)), JobId: uint(idx)}
	}
}

func ConnectWorker(id uint, decoys <-chan jobTuple) {
	jobsCompleted := 0
	var decoy *pb.TLSDecoySpec
	var err error

	for decoyTuple := range decoys {
		jobsCompleted++

		decoy = decoyTuple.Decoy
		fmt.Printf("[%d/%d/%d] (%d) Connecting to decoy %s -- %s ... \n",
			jobsCompleted, decoyTuple.JobId, decoyTuple.Total, id, decoy.GetHostname(), decoy.GetIpAddrStr())

		err = ConnectSpecial(decoy)
		if err != nil {
			fmt.Printf("[%d/%d/%d] (%d) Failure: %s\n",
				jobsCompleted, decoyTuple.JobId, decoyTuple.Total, id, err.Error())
		} else {
			fmt.Printf("[%d/%d/%d] (%d) Success\n",
				jobsCompleted, decoyTuple.JobId, decoyTuple.Total, id)
		}
	}
}

func ConnectSpecial(decoy *pb.TLSDecoySpec) error {

	timeout := time.Duration(5 * time.Second)

	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", decoy.GetIpAddrStr())
	if err != nil {
		return err
	}

	fmt.Fprintf(conn, "'This must be Thursday,' said Arthur to himself, sinking low over his beer. 'I never could get the hang of Thursdays.'")

	conn.Close()
	return nil
}
