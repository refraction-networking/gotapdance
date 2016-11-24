package main

import (
	"github.com/SergeyFrolov/gotapdance/tapdance"
	"golang.org/x/mobile/asset"
)

func main() {
	// Read keyfile
	pubkeyFile, err := asset.Open("pubkey.dev")
	if err != nil {
		panic(err)
	}
	defer pubkeyFile.Close()
	staionPubkey := make([]byte, 32)

	_, err = pubkeyFile.Read(staionPubkey)
	if err != nil {
		panic(err)
	}
	// TODO: check if 32 bytes

	// Read root.pem
	rootPemFile, err := asset.Open("root.pem")
	if err != nil {
		panic(err)
	}
	defer rootPemFile.Close()
	stationRootPem := make([]byte, 524288)
	rootPemLen, err := rootPemFile.Read(stationRootPem)
	//rootpem_len, err := rootpem_file.Read(station_rootpem)
	if err != nil {
		panic(err)
	}

	tapdanceProxy := tapdance.NewTapdanceProxyByKeys(10500, staionPubkey, stationRootPem[0:rootPemLen])
	tapdanceProxy.Listen()
}
