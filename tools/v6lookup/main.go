package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jinzhu/copier"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func main() {

	var assets_file = flag.String("f", "ClientConf", "The ClientConf")
	var out_fname = flag.String("o", "", "`output` file name to write new/modified config")
	var noout = flag.Bool("noout", false, "Don't print ClientConf")
	var lookupV6 = flag.Bool("l6", false, "Perform AAAA DNS lookup for all hostnames and add to TlsDecoySpec")
	flag.Parse()

	fmt.Printf("Looking up IPv6 addresses for Conf (%s) \n", *assets_file)

	if *assets_file == "" {
		fmt.Println("Please provide a clientConf file.")
		os.Exit(1)
	}

	clientConf := &pb.ClientConf{}

	// Parse ClientConf
	clientConf = parseClientConf(*assets_file)

	// v6Decoys := lookupHosts(clientConf.DecoyList.GetTlsDecoys())
	// fmt.Printf("Found %d Ipv6 Decoys\n", len(v6Decoys))
	if *lookupV6 {
		v6Decoys := make([]*pb.TLSDecoySpec, 0)
		var ipv6Arr [16]byte
		uniqueIPv6Addrs := make(map[[16]byte]bool)
		ipv6Decoys := make(chan *pb.TLSDecoySpec, 1)
		i := 0

		go func() {
			for decoy := range ipv6Decoys {
				fmt.Printf("%v", decoy.GetHostname())
				copy(ipv6Arr[:], decoy.GetIpv6Addr()[:16])
				if uniqueIPv6Addrs[ipv6Arr] == false {
					uniqueIPv6Addrs[ipv6Arr] = true
					v6Decoys = append(v6Decoys, decoy)
					fmt.Printf("%v, %v\n", decoy.GetHostname(), decoy.GetIpAddrStr())
					i++
				}
			}
		}()

		for _, decoy := range clientConf.DecoyList.GetTlsDecoys() {
			lookupHost(decoy, ipv6Decoys)
		}

		fmt.Printf("Unique Addresses: %v\n", i)

		for _, decoy := range v6Decoys {
			clientConf.DecoyList.TlsDecoys = append(clientConf.DecoyList.TlsDecoys, decoy)
		}
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

func lookupHost(decoy *pb.TLSDecoySpec, ip6Chan chan *pb.TLSDecoySpec) {

	decoyHostname := decoy.GetHostname()
	decoyIPs, err := net.LookupIP(decoyHostname)
	if err == nil && decoyIPs != nil {
		for _, decoyIP := range decoyIPs {
			if decoyIP.To4() != nil {
				continue
			}
			newDecoy := DeepCopy(decoy)
			newDecoy.Ipv6Addr = decoyIP
			newDecoy.Ipv4Addr = nil
			fmt.Printf("%v, %v, (%v), [%v]\n", len(decoyIPs), decoyHostname, decoy.GetIpAddrStr(), decoyIP)
			ip6Chan <- newDecoy
		}
	}
	return
}

func lookupHosts(decoyList []*pb.TLSDecoySpec) map[string][]byte {
	v6Decoys := make(map[string][]byte)

	for _, decoy := range decoyList {
		decoyHostname := decoy.GetHostname()
		decoyIP, err := net.ResolveIPAddr("ip6", decoyHostname)
		if err == nil && decoyIP != nil {
			ipBytes := []byte(decoyIP.IP.To16())
			if ipBytes != nil {
				v6Decoys[decoyHostname] = ipBytes
			}
			fmt.Printf("%v -(%v)- %v\n", decoyHostname, decoy.GetIpAddrStr(), decoyIP)
		}
	}
	return v6Decoys
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

type jobTuple struct {
	Decoy *pb.TLSDecoySpec
	Total uint
	JobId uint
}

// DeepCopy - Create a Deep Copy of a given TLSDecoySpec Object
func DeepCopy(ds *pb.TLSDecoySpec) *pb.TLSDecoySpec {
	newDs := pb.TLSDecoySpec{}
	copier.Copy(&newDs, ds)
	return &newDs
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

func printClientConf(clientConf *pb.ClientConf) {
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
		// ip6 := net.IP{}
		// ip6.UnmarshalText(decoy.GetIpv6Addr())
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
	// if clientConf.GetDarkDecoyBlocks() != nil {
	// 	darkDecoyBlocks := clientConf.DarkDecoyBlocks.Blocks
	// 	fmt.Printf("\nDark Decoy Blocks: %d blocks\n", len(darkDecoyBlocks))
	// 	for i, block := range darkDecoyBlocks {
	// 		fmt.Printf("%d:\n  %s\n", i, block)
	// 	}
	// }
}
