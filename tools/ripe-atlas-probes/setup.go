package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	atlas "github.com/keltia/ripe-atlas"
)

const (
	TracerouteCost   = 30
	DNSCost          = 10
	OneOffMultiplier = 2
)

func main() {
	targetsFilename := flag.String("t", "targets.json", "The JSON file from which probe targets are loaded. They can be specified by IPv4 addresses or hostnames.")
	key := flag.String("key", "", "The RIPE Atlas API key used to run the measurements.")
	probesFilename := flag.String("p", "probes.json", "The JSON file from which probes are loaded. See https://atlas.ripe.net/docs/api/v2/manual/measurements/types/in_detail.html for information on the format.")
	arg := flag.String("arg", "", "The DNS lookup argument to use in measurements.")
	verbose := flag.Bool("v", false, "Print out lots of information about RIPE Atlas API requests.")

	flag.Parse()

	if *key == "" {
		fmt.Fprintln(os.Stderr, "You must specify an API key.")
		os.Exit(1)
	}

	if *arg == "" {
		fmt.Fprintln(os.Stderr, "You must specify a query argument.")
		os.Exit(1)
	}

	targetsFile, err := os.Open(*targetsFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, `Couldn't open targets file "%s": %s\n`, *targetsFilename, err)
		os.Exit(1)
	}
	defer targetsFile.Close()

	var targets []string
	err = json.NewDecoder(targetsFile).Decode(&targets)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't decode targets file:", err)
		os.Exit(1)
	}

	probesFile, err := os.Open(*probesFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, `Couldn't open probes file "%s": %s\n`, *targetsFilename, err)
		os.Exit(1)
	}
	defer probesFile.Close()

	var probes []atlas.ProbeSet
	err = json.NewDecoder(probesFile).Decode(&probes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't decode probes file:", err)
		os.Exit(1)
	}

	var totalProbes int
	for _, p := range probes {
		totalProbes += p.Requested
	}

	config := atlas.Config{
		APIKey:  *key,
		Verbose: *verbose,
	}
	if *verbose {
		config.Level = 2
	}

	client, err := atlas.NewClient(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create RIPE Atlas client:", err)
		os.Exit(1)
	}

	credits, err := client.GetCredits()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to get credits information for RIPE Atlas account:", err)
		os.Exit(1)
	}

	creditEstimate := OneOffMultiplier * (TracerouteCost + DNSCost) * len(targets) * totalProbes
	fmt.Printf("You have %d credits. By my estimation, these measurements could take up to %d credits (depending on how many probes are available). Do you want to continue? [y/N] ", credits.CurrentBalance, creditEstimate)

inputLoop:
	for {
		var input string
		_, err = fmt.Scanf("%s", &input)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read input:", err)
			os.Exit(1)
		}

		switch strings.ToLower(input) {
		case "y", "yes":
			break inputLoop
		case "n", "no":
			os.Exit(0)
		default:
			fmt.Printf(`I don't know what "%s" means. Please answer y or N. `, input)
		}
	}

	fmt.Println("Creating measurements...")

	dnsDefinitions := make([]atlas.Definition, 0, len(targets))
	tracerouteDefinitions := make([]atlas.Definition, 0, len(targets))

	tag := "refraction-routing-probe-" + time.Now().Format("2006-01-02-15-04-05")

	for _, target := range targets {
		dns := atlas.Definition{
			Description:   "DNS routing probe for " + target,
			Tags:          []string{tag},
			Type:          "dns",
			AF:            4,
			IsOneoff:      true,
			IsPublic:      false,
			QueryClass:    "IN",
			QueryType:     "A",
			Target:        target,
			QueryArgument: *arg,
		}
		dnsDefinitions = append(dnsDefinitions, dns)

		traceroute := atlas.Definition{
			Description: "Traceroute routing probe for " + target,
			Tags:        []string{tag},
			Type:        "traceroute",
			AF:          4,
			Protocol:    "UDP",
			IsOneoff:    true,
			IsPublic:    false,
			Target:      target,
		}
		tracerouteDefinitions = append(tracerouteDefinitions, traceroute)
	}

	tracerouteRequest := client.NewMeasurement()
	tracerouteRequest.Definitions = tracerouteDefinitions
	tracerouteRequest.Probes = probes

	tracerouteResp, err := client.Traceroute(tracerouteRequest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create traceroute measurements:", err)
		os.Exit(1)
	}

	fmt.Println("Successfully created traceroute measurements. Waiting for information on probes to proceed to DNS measurements.")

	body := struct {
		Probes []struct {
			ID int `json:"id"`
		} `json:"probes"`
	}{}

	for len(body.Probes) == 0 {
		// It seems like RIPE's API takes a bit of an eventual consistency model,
		// so the probes aren't immediately available after creating the request.
		// Keep trying until we get a non-empty probes array.
		time.Sleep(10 * time.Second)

		// The client doesn't allow us to get the probes of a measurement. :(
		req, err := http.NewRequest("GET", fmt.Sprintf("https://atlas.ripe.net/api/v2/measurements/%d?fields=probes", tracerouteResp.Measurements[0]), nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to create probes request:", err)
			os.Exit(1)
		}

		req.Header.Add("Authorization", "Key "+*key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get measurement:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		err = json.NewDecoder(resp.Body).Decode(&body)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to parse probes from measurement:", err)
			os.Exit(1)
		}
	}

	fmt.Println("Using probes for DNS requests:", body.Probes)

	probeIDs := make([]string, 0, totalProbes)
	for _, probe := range body.Probes {
		probeIDs = append(probeIDs, strconv.Itoa(probe.ID))
	}

	probesString := strings.Join(probeIDs, ",")

	dnsRequest := client.NewMeasurement()
	dnsRequest.Definitions = dnsDefinitions
	dnsRequest.Probes = []atlas.ProbeSet{{Requested: len(probeIDs), Type: "probes", Value: probesString}}

	_, err = client.DNS(dnsRequest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create DNS measurements:", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully created measurements! To fetch the results, run the following command in a few minutes:\n\n")
	fmt.Printf("    curl -H \"Authorization: Key %s\" https://atlas.ripe.net/api/v2/measurements/tags/%s/results/ > results.json\n", *key, tag)
}
