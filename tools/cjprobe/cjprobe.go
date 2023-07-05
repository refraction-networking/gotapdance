package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/conjure/proto"
	log "github.com/sirupsen/logrus"
)

var specialUDPEncoded = "\x38xCKe9ECO5lNwXgd5Q25w0C2qUR7whltkA8BbyNokGIp5rzzm0hc7yqbR\x38FAP3S9w7oLrvvei7IphdwZEKUvF5iZeSdtDFEDc6cIDiv11aTNkOp08k\x38mRISHvoeSWSgMOjkbR2un5XKpJEZIK31Bc2obUGRIoY2tpxm6RUV5nOU\x07SuifuqZ"
var specialUDPPayload = "xCKe9ECO5lNwXgd5Q25w0C2qUR7whltkA8BbyNokGIp5rzzm0hc7yqbR.FAP3S9w7oLrvvei7IphdwZEKUvF5iZeSdtDFEDc6cIDiv11aTNkOp08k.mRISHvoeSWSgMOjkbR2un5XKpJEZIK31Bc2obUGRIoY2tpxm6RUV5nOU.SuifuqZ"
var specialUDPPort = 53

func main() {

	decoyOnly := flag.Bool("d", false, "Only scan decoy addresses, ignore subnets from clientconf or command line args")
	subnetOnly := flag.Bool("s", false, "Only scan subnet blocks, ignore decoys from clientconf or command line args")
	addressesPerSubnet := flag.Int("sa", 1, "Number of addresses to choose from each subnet")
	subnetSeed := flag.Int64("ss", -1, "Seed for random selection of address from subnet blocks")

	excludeV6 := flag.Bool("no6", false, "Ignore IPv6 decoys and subnets when probing")

	workers := flag.Int("w", 20, "Number of parallel workers for the connect_to_all test")

	fname := flag.String("f", "", "`ClientConf` file to parse")
	port := flag.Int("p", 53, "Destination port of all probes sent")

	quiet := flag.Bool("q", false, "Quiet mode - prevents probe result logging")

	customTag := flag.String("tag", "", "Set a custom tag to be sent over the probe. Only works with raw UDP packet mode")
	customURL := flag.String("url", "", "Set a custom domain string for DNS lookup. Only works with DNS request mode")

	useDNS := flag.Bool("dns", false, "Send the tag as a DNS request (uses golang DNS lookup sending 8 probes)")

	flag.Parse()

	// Quick compatibility check
	if *decoyOnly && *subnetOnly {
		log.Warn("Decoy only (-d) and Subnet only (-s) conflict, use only one.")
		flag.Usage()
		os.Exit(1)
	}

	// Set the payload and port if they were set by command line arg
	if *customURL != "" {
		specialUDPPayload = *customURL
	}
	if *customTag != "" {
		specialUDPEncoded = *customTag
	}
	if *port != 53 {
		specialUDPPort = *port
	}

	var targets = []string{}
	var subnets = []*net.IPNet{}

	// parse args as decoy addresses or subnets
	for _, arg := range flag.Args() {
		_, subnet, err := net.ParseCIDR(arg)
		if err == nil {
			if !*decoyOnly {
				subnets = append(subnets, subnet)
			}
		} else if addr := net.ParseIP(arg); addr != nil {
			if !*subnetOnly {
				targets = append(targets, addr.String())
			}
		} else {
			if !*quiet {
				log.Warnf("failed to parse target \"%s\"", arg)
			}
		}
	}

	// parse decoys from clientconf into string array
	var clientConf *pb.ClientConf
	var err error
	if *fname != "" {
		clientConf, err = parseClientConf(*fname)
		if err != nil {
			log.Fatal(err)
		}

		if !*subnetOnly {
			for _, decoy := range clientConf.GetDecoyList().TlsDecoys {
				// Decoy string includes port which we do not want
				addr := strings.Split(decoy.GetIpAddrStr(), ":")[0]
				targets = append(targets, addr)
			}
		}
		if !*decoyOnly {
			log.Warnf("Not currently implemented")
			// if blocks := clientConf.GetPhantomSubnetsList(); blocks != nil {
			// 	for _, subnetStr := range blocks.Blocks {
			// 		_, subnet, err := net.ParseCIDR(subnetStr)
			// 		if err != nil {
			// 			continue
			// 		}
			// 		subnets = append(subnets, subnet)
			// 	}
			// }
		}
	}
	// select random addresses from subnets
	targets = append(targets, selectFromSubnets(subnets, *addressesPerSubnet, *subnetSeed)...)

	// de-duplicate addresses in list
	targets = removeDuplicateValues(targets)

	// Exclude v6 addresses if option is specified.
	if *excludeV6 {
		log.Info("excluding IPv6 targets")
		targets = removeIPv6Addrs(targets)
	}

	// fmt.Printf("so: %v, sa: %v, ss:%v, do:%v, no6:%v, wrkrs:%d, cc:%s, p: %v, q: %v, args: %+v\n",
	// 	*subnetOnly, *addressesPerSubnet, *subnetSeed, *decoyOnly, *excludeV6, *workers, *fname, *port, *quiet, flag.Args())

	// fmt.Println(targets, subnets)
	ConnectToAll(targets, *workers, *quiet, *useDNS)
}

func parseClientConf(fname string) (*pb.ClientConf, error) {

	clientConf := pb.ClientConf{}
	buf, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("Error reading file - %v", err)
	}
	err = proto.Unmarshal(buf, &clientConf)
	if err != nil {
		return nil, fmt.Errorf("Error parsing ClientConf - %v", err)
	}
	return &clientConf, nil
}

type jobTuple struct {
	Target string
	Total  uint
	JobID  uint
}

// ConnectToAll parallelizes the process pg sending tagged packets to hosts.
func ConnectToAll(targets []string, workers int, quiet bool, useDNS bool) {

	if !quiet {
		log.Info("Connection to all registration decoys in client conf.")
	}
	var wg sync.WaitGroup

	jobChan := make(chan jobTuple, len(targets))

	for id := 0; id < workers; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			jobsCompleted := 0
			var err error

			for jobTuple := range jobChan {

				target := jobTuple.Target
				output := fmt.Sprintf("[%d/%d/%d] (%d) Connecting to decoy %s ... ",
					jobsCompleted, jobTuple.JobID, jobTuple.Total, id, target)

				start := time.Now()
				if useDNS {
					err = ConnectSpecialDNS(target, specialUDPPayload)
				} else {
					err = ConnectSpecial(target, specialUDPEncoded)
				}
				duration := time.Since(start)
				if !quiet {
					if err != nil {
						output += fmt.Sprintf("%d Failure: %s\n", duration.Milliseconds(), err.Error())
						log.Warn(output)
					} else {
						output += fmt.Sprintf("%d Success\n", duration.Milliseconds())
						log.Info(output)
					}
				}
				jobsCompleted++
			}

		}(id) // end go worker func
	}

	go func() {
		total := uint(len(targets))
		for idx, target := range targets {
			jobChan <- jobTuple{Target: target, Total: total, JobID: uint(idx)}
		}
		close(jobChan)
	}()

	wg.Wait()
}

// ConnectSpecial sends a raw UDP packet with the tag specified. `target` must be an IP address.
func ConnectSpecial(target, tag string) error {
	conn, err := net.Dial("udp", net.JoinHostPort(target, fmt.Sprint(specialUDPPort)))
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Fprintf(conn, tag)

	return nil
}

func removeDuplicateValues(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	// If the key(values of the slice) is not equal
	// to the already present value in new slice (list)
	// then we append it. else we jump on another element.
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func removeIPv6Addrs(addrSlice []string) []string {
	return []string{}
}

// ConnectSpecialDNS sends the special tag as a DNS request and ignores any response. This uses
// The golang DNS resolution, so it may result in retries or longer timeouts as we do not expect
// targets to actually function as DNS resolvers.
func ConnectSpecialDNS(target, tag string) error {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, "udp", net.JoinHostPort(target, fmt.Sprint(specialUDPPort)))
		},
	}
	_, err := r.LookupHost(context.Background(), tag)
	return err
}

func selectFromSubnets(subnets []*net.IPNet, aps int, seed int64) []string {
	list := []string{}

	if seed != -1 {
		rand.Seed(seed)
	}
	for _, subnet := range subnets {
		for i := 0; i < aps; i++ {

			randomBytes := make([]byte, len(subnet.IP))
			_, err := rand.Read(randomBytes)
			if err != nil {
				continue
			}

			addressBytes := subnet.IP.Mask(subnet.Mask)
			newAddr := []byte{}
			for idx, b := range subnet.Mask {
				randMask := randomBytes[idx] & (^b)
				newAddr = append(newAddr, randMask|addressBytes[idx])
			}

			addr := net.IP(newAddr).String()
			list = append(list, addr)
		}
	}

	return list
}
