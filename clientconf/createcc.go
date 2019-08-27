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
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func main() {

	var assets_file = flag.String("f", "ClientConf", "The ClientConf")
	var ip_file = flag.String("i", "logfile.txt", "The list of valid IP's")
	var out_fname = flag.String("o", "", "`output` file name to write new/modified config")
	var noout = flag.Bool("noout", false, "Don't print ClientConf")

	flag.Parse()

	fmt.Printf("Intersecting client conf (%s) with IP list(%s)\n", *assets_file, *ip_file)

	clientConf := pb.ClientConf{}
	ipList := parseIpList(*ip_file)

	// Parse ClientConf
	if *assets_file != "" {
		clientConf = parseClientConf(*assets_file)
	}

	decoyList := DecoyInsersect(clientConf.DecoyList.GetTlsDecoys(), ipList)

	clientConf.DecoyList = &pb.DecoyList{TlsDecoys: decoyList}

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

func DecoyInsersect(decoyList []*pb.TLSDecoySpec, filterIPs map[string]bool) []*pb.TLSDecoySpec {
	var resultList []*pb.TLSDecoySpec
	var decoyIp string

	for _, decoy := range decoyList {
		decoyIp = decoy.GetIpAddrStr()
		if _, ok := filterIPs[decoyIp]; ok {
			resultList = append(resultList, decoy)
		}
	}
	return resultList
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

func parseIpList(fname string) map[string]bool {
	result := make(map[string]bool)

	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addr, port, err := ParseIpPort(scanner.Text())
		if err != nil {
			continue
		}
		result[addr+":"+port] = true
	}

	return result
}

func ParseIpPort(ipStr string) (string, string, error) {
	splitStr := strings.Split(ipStr, ":")
	if len(splitStr) < 2 {
		return "", "", fmt.Errorf("Malformed address (possibly no port specified: %s", ipStr)
	}

	addr := net.ParseIP(splitStr[0])
	if addr == nil {
		return "", "", fmt.Errorf("Unable to parse address: %s", splitStr[0])
	}

	port, err := strconv.ParseInt(splitStr[1], 10, 32)
	if err != nil || port < 2^16 {
		return "", "", fmt.Errorf("Unable to parse port: %s", splitStr[1])
	}

	return splitStr[0], splitStr[1], nil
}

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
