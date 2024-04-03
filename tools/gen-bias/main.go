package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/refraction-networking/conjure/pkg/phantoms"
	pb "github.com/refraction-networking/conjure/proto"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

func main() {
	defaultSeed := "5a87133b68ea3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f"
	defaultSalt := "phantom-bias-test"
	defaultConfigPath := "../assets/ClientConf"
	defaultOutFile := "./bias.out"

	var seedStr, saltStr, inFile, outFile string
	var v6, both bool
	var cliVersion uint

	flag.StringVar(&seedStr, "seed", defaultSeed, "Overrides the default seed for phantom selection")
	flag.StringVar(&saltStr, "salt", defaultSalt, "Overrides the default salt for phantom selection")
	flag.StringVar(&inFile, "f", defaultConfigPath, "Filepath to look for the parse-able conjure ClientConfig")
	flag.StringVar(&outFile, "o", defaultOutFile, "Filepath to write output bias into")
	flag.BoolVar(&v6, "v6", false, "Generate bias output for IPv6 subnets only")
	flag.BoolVar(&both, "both", false, "Generate bias output for BOTH IPv4 and IPv6 subnets")
	flag.UintVar(&cliVersion, "version", 1, "Client library version to generate bias for")

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

	os.Setenv("PHANTOM_SUBNET_LOCATION", "/dev/null")
	phantomSelector, err := phantoms.NewPhantomIPSelector()
	if err != nil {
		panic(err)
	}

	subnetConfig := phantoms.SubnetConfig{WeightedSubnets: ps.WeightedSubnets}
	newGen := phantomSelector.AddGeneration(-1, &subnetConfig)

	totTrials := 1_000_000
	for i := 0; i < totTrials; i++ {
		curSeed := expandSeed(seed, salt, i)
		addr, err := phantomSelector.Select(curSeed, newGen, cliVersion, v6)
		if err != nil {
			continue
		}
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
