package tapdance

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"reflect"
	"testing"
)

func TestAssets_Decoys(t *testing.T) {
	oldpath := Assets().path
	Assets().saveDecoys()
	dir1, err := ioutil.TempDir("/tmp/", "decoy1")
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	dir2, err := ioutil.TempDir("/tmp/", "decoy2")
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}

	var testDecoys1 = []decoyServer{
		{IP: "4.8.15.16", SNI: "ericw.us"},
		{IP: "19.21.23.42", SNI: "sergeyfrolov.github.io"},
	}
	var testDecoys2 = []decoyServer{
		{IP: "0.1.2.3", SNI: "whatever.cn"},
		{IP: "255.254.253.252", SNI: "particular.ir"},
		{IP: "11.22.33.44", SNI: "what.is.up"},
		{IP: "8.255.255.8", SNI: "heh.meh"},
	}

	Assets().SetAssetsDir(dir1)
	err = Assets().SetDecoys(testDecoys1)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	Assets().SetAssetsDir(dir2)
	err = Assets().SetDecoys(testDecoys2)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	if !reflect.DeepEqual(Assets().decoys, testDecoys2) {
		fmt.Println("Assets are not equal!")
		fmt.Println("Assets().decoys:", Assets().decoys)
		fmt.Println("testDecoys2:", testDecoys2)
		t.Fail()
	}

	decoyInList := func(d decoyServer, decoyList []decoyServer) bool {
		for _, elem := range decoyList {
			if elem == d {
				return true
			}
		}
		return false
	}

	for i := 0; i < 10; i++ {
		_sni, addr := Assets().GetDecoyAddress()
		host_addr, _, err := net.SplitHostPort(addr)
		if err != nil {
			fmt.Println("Corrupted addr:", addr, ". Error:", err.Error())
			t.Fail()
		}
		decoyServ := decoyServer{SNI: _sni, IP: host_addr}
		if !decoyInList(decoyServ, Assets().decoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().decoys)
			t.Fail()
		}
	}
	Assets().SetAssetsDir(dir1)
	if !reflect.DeepEqual(Assets().decoys, testDecoys1) {
		fmt.Println("Assets are not equal!")
		fmt.Println("Assets().decoys:", Assets().decoys)
		fmt.Println("testDecoys1:", testDecoys1)
		t.Fail()
	}
	for i := 0; i < 10; i++ {
		_sni, addr := Assets().GetDecoyAddress()
		host_addr, _, err := net.SplitHostPort(addr)
		if err != nil {
			fmt.Println("Corrupted addr:", addr, ". Error:", err.Error())
			t.Fail()
		}
		decoyServ := decoyServer{SNI: _sni, IP: host_addr}
		if !decoyInList(decoyServ, Assets().decoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().decoys)
			t.Fail()
		}
	}
	os.Remove(path.Join(dir1, Assets().filenameDecoys))
	os.Remove(path.Join(dir2, Assets().filenameDecoys))
	os.Remove(dir1)
	os.Remove(dir2)
	Assets().SetAssetsDir(oldpath)
	fmt.Println("TestAssets_Decoys OK")
}

func TestAssets_Pubkey(t *testing.T) {
	oldpath := Assets().path
	Assets().savePubkey()
	dir1, err := ioutil.TempDir("/tmp/", "pubkey1")
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	dir2, err := ioutil.TempDir("/tmp/", "pubkey2")
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}

	var pubkey1 = [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
		27, 28, 29, 30, 31}
	var pubkey2 = [32]byte{200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
		212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
		227, 228, 229, 230, 231}

	Assets().SetAssetsDir(dir1)
	err = Assets().SetPubkey(pubkey1)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	Assets().SetAssetsDir(dir2)
	err = Assets().SetPubkey(pubkey2)
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	if !bytes.Equal(Assets().stationPubkey[:], pubkey2[:]) {
		fmt.Println("Pubkeys are not equal!")
		fmt.Println("Assets().stationPubkey:", Assets().stationPubkey)
		fmt.Println("pubkey2:", pubkey2)
		t.Fail()
	}

	Assets().SetAssetsDir(dir1)
	if !bytes.Equal(Assets().stationPubkey[:], pubkey1[:]) {
		fmt.Println("Pubkeys are not equal!")
		fmt.Println("Assets().stationPubkey:", Assets().stationPubkey)
		fmt.Println("pubkey1:", pubkey1)
		t.Fail()
	}
	os.Remove(path.Join(dir1, Assets().filenameStationPubkey))
	os.Remove(path.Join(dir2, Assets().filenameStationPubkey))
	os.Remove(dir1)
	os.Remove(dir2)
	Assets().SetAssetsDir(oldpath)
	fmt.Println("TestAssets_Pubkey OK")
}
