package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/refraction-networking/gotapdance/tapdance/phantoms"
	"golang.org/x/crypto/hkdf"
)

func main() {
	defaultSeed := "5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f"
	defaultSalt := "phantom-bias-test"
	defaultConfigPath := "../assets/ClientConf"
	defaultOutFile := "./bias.out"

	var seedStr, saltStr, inFile, outFile string
	var v6, both bool

	flag.StringVar(&seedStr, "seed", defaultSeed, "Overrides the default seed for phantom selection")
	flag.StringVar(&saltStr, "salt", defaultSalt, "Overrides the default salt for phantom selection")
	flag.StringVar(&inFile, "f", defaultConfigPath, "Filepath to look for the parse-able conjure ClientConfig")
	flag.StringVar(&outFile, "o", defaultOutFile, "Filepath to write output bias into")
	flag.BoolVar(&v6, "v6", false, "Generate bias output for IPv6 subnets only")
	flag.BoolVar(&both, "both", false, "Generate bias output for BOTH IPv4 and IPv6 subnets")

	flag.Parse()

	seed, err := hex.DecodeString(seedStr)
	if err != nil {
		panic(err)
	}

	salt := []byte(saltStr)

	clientConf, err := parseClientConf(inFile)
	if err != nil {
		panic(err)
	}

	ps := clientConf.GetPhantomSubnetsList()
	ipCount := map[string]int{}

	transform := phantoms.V4Only
	if v6 {
		transform = phantoms.V6Only
	} else if both {
		transform = nil
	}

	//snets, err := parseSubnets(getSubnets(ps, nil, true))
	//require.Nil(t, err)
	//for snet := range snets {
	//}
	totTrials := 1_000_000
	for i := 0; i < totTrials; i++ {
		curSeed := expandSeed(seed, salt, i)
		addr, err := phantoms.SelectPhantom(curSeed, ps, transform, true)
		//addr, err := SelectPhantom(curSeed, ps, nil, true)
		if err != nil {
			continue
		}
		//require.Nil(t, err)
		ipCount[addr.String()]++
	}
	// Write file
	f, err := os.Create(outFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	for ip, count := range ipCount {
		f.WriteString(fmt.Sprintf("%s %d\n", ip, count))
	}
}

func expandSeed(seed, salt []byte, i int) []byte {
	bi := make([]byte, 8)
	binary.LittleEndian.PutUint64(bi, uint64(i))
	return hkdf.Extract(sha256.New, seed, append(salt, bi...))
}

func parseClientConf(fname string) (*pb.ClientConf, error) {

	clientConf := &pb.ClientConf{}
	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(buf, clientConf)
	if err != nil {
		return nil, err
	}
	return clientConf, nil
}
