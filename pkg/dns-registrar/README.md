# Conjure DNS Registrar Proof of Concept

## Setup

Point your domain's nameserver address to your server. Follow [dnstt's DNS setup](https://www.bamsoftware.com/software/dnstt/#dns-setup) to setup a nameserver record for your subdomain

## Build

Clone the repo:
```sh
https://github.com/mingyech/conjure-dns-registrar
```
Build server:
```sh
cd conjure-dns-registrar/cmd/server
go get
go build
```
Build client:
```sh
cd conjure-dns-registrar/cmd/client
go get
go build
```
## Usage

First generate a keypair on  server:
```sh
./server -genkey -privkeyfilename 'server.key' -pubkeyfilename 'server.pub'
```
Then start the server, you may need root to use port 53:
```sh
./server -addr '[::]:53' -domain 'a.bc' -privkey 'server.key' -msg 'it works'
```
Start the client:
```sh
./client -domain 'a.bc' -udp '1.1.1.1:53' -pubkey 'server.pub' -msg 'hi'
```