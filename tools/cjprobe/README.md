
# Conjure Prober

This tool is a testing system for measuring conjure station reachability. Each station watches for
UDP packets containing a special string, and logs source and destination IP addresses when it is
detected. This allows a station operator to run this tool from disparate locations and validate that
traffic routes past a designated station. [Station string checking](https://github.com/refraction-networking/conjure/blob/da349002ae89bf05b3fa2a3197ae2d3b8eefa3f9/src/process_packet.rs#L353)
can be seen here.

For compatibility with RIPE atlas this was designed be sent as a DNS lookup
request with the special string as the domain. In this tool we send the DNS encoded version of the
tag as a raw UDP packet. This tool does provide the option `-dns` which causes this tool to use
the golang DNS lookup system but this is not the default behavior.

In general UDP was chosen because it allows us to send the packet without participation on the side of the
target address. This allows us to validate Phantom addresses even if no host resides at the address
(which would be impossible for any TCP based probe).

## Usage

```sh
cjprobe [options] [TARGETS...]:
  -d    Only scan decoy addresses, ignore subnets from clientconf or command line args
  -dns
        Send the tag as a DNS request (uses golang DNS lookup sending 8 probes)
  -f ClientConf
        ClientConf file to parse
  -no6
        Ignore IPv6 decoys and subnets when probing
  -p int
        Destination port of all probes sent (default 53)
  -q    Quiet mode - prevents probe result logging
  -s    Only scan subnet blocks, ignore decoys from clientconf or command line args
  -sa int
        Number of addresses to choose from each subnet (default 1)
  -ss int
        Seed for random selection of address from subnet blocks (default -1)
  -tag string
        Set a custom tag to be sent over the probe. Only works with raw UDP packet mode
  -url string
        Set a custom domain string for DNS lookup. Only works with DNS request mode
  -w int
        Number of parallel workers for the connect_to_all test (default 20)
```

For example to scan all decoys from a given clientconf you could run the following. Currently
phantom subnets CAN be stored in the Clientconf struct, but no distributed ClientConf contains
phantom subnets (this will come soon).

```sh
cjprobe -f ../assets/ClientConf
```

Subnets and decoy address targets can also be specified in the tailing args. To perform a scan that
uses 5 addresses from each phantom subnet provided chosen in a reproducible way we can use the `-sa`
option to set the `addresses-per-subnet` and the `-ss` option to set the `subnet-seed`. This selects
from two subnets, supporting ipv4 and ipv6.

```sh
cjprobe -sa 5 -ss 100 10.0.0.1/8 2106:abcd::1/32
```

To send a DNS query we can provide the `-dns` flag. Note that when
using the `-dns` option that there is no control over retries, so addresses not running public
DNS resolvers will force golang to send 8 DNS requests per address. As shown below we can also mix
our tailing targets between subnets and decoy addresses.

```sh
cjprobe -dns 8.8.8.8 1.1.1.1 128.138.0.1/16
```

## Notes

Many clientconfigs have duplicate decoy addresses as there are multiple domain names that reference
the same decoy IP address. This tool automatically de-duplicates before sending probes, so the probe
function is only called once for each address.
