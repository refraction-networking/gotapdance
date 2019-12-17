package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func printClientConf(clientConf pb.ClientConf) {
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

func ConnectToAll(decoyList []*pb.TLSDecoySpec, workers int) {

	fmt.Println("Connection to all registration decoys in client conf.")
	var wg sync.WaitGroup

	decoyChan := make(chan jobTuple, len(decoyList))

	for id := 0; id < workers; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			jobsCompleted := 0
			var decoy *pb.TLSDecoySpec
			var err error

			for decoyTuple := range decoyChan {

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
				jobsCompleted++
			}

		}(id) // end go worker func
	}

	go func() {
		for idx := 0; idx < len(decoyList); idx++ {
			decoyChan <- jobTuple{Decoy: decoyList[idx], Total: uint(len(decoyList)), JobId: uint(idx)}
		}
		close(decoyChan)
	}()

	wg.Wait()
}

func ConnectSpecial(decoy *pb.TLSDecoySpec) error {

	timeout := time.Duration(5 * time.Second)

	conn, err := net.DialTimeout("tcp", decoy.GetIpAddrStr(), timeout)
	if err != nil {
		return err
	}
	defer closeConn(conn, decoy.GetIpAddrStr())

	fmt.Fprintf(conn, "'This must be Thursday,' said Arthur to himself, sinking low over his beer. 'I never could get the hang of Thursdays.'")

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		// fmt.Printf("SetReadDeadline failed: %s", err.Error())
		return nil
	}

	recvBuf := make([]byte, 1024)

	_, err = conn.Read(recvBuf[:]) // recv data
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// fmt.Printf("read timeout: %s", err.Error())
			return nil
			// time out
		} else {
			// fmt.Printf("read error: %s", err.Error())
			return nil
		}
	}

	return nil
}

func closeConn(conn net.Conn, addr string) {
	// fmt.Printf("Closing connection to: %s\n", addr)
	conn.Close()

}
