# Tools 

Tools for Refraction Networking development.

To build use:

```sh
# To build all binaries
$ make

# To build one specific one
$ make clientconf

```

## Client Conf

`clientconf`

Client Config management tools. Used for adding 

## IPv6 Lookup

`v6lookup`

Perform a AAAA lookup for each domain name as part of clientConfig supplement for Conjure.

## CJProbe

`cjprobe`

Run UDP probe tool to test station reachability. Sends raw UDP packets or DNS requests containing
string tag the conjure stations look for and log, validating that a station lies on path for a
client, server pair.

## Elligator Test

`elligator-test`

Tests to ensure that the elligator functionality implemented here in golang will match that of the station implementation.

## uTLS test

`utls-test`

Test various utls fingerprints against decoys in the ClientConf.
