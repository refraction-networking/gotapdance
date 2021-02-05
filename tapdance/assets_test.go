package tapdance

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestAssets_Decoys(t *testing.T) {
	var b bytes.Buffer
	logHolder := bufio.NewWriter(&b)
	oldLoggerOut := Logger().Out
	Logger().Out = logHolder
	defer func() {
		Logger().Out = oldLoggerOut
		if t.Failed() {
			logHolder.Flush()
			fmt.Printf("TapDance log was:\n%s\n", b.String())
		}
	}()
	oldpath := Assets().path
	Assets().saveClientConf()
	dir1, err := ioutil.TempDir("/tmp/", "decoy1")
	if err != nil {
		fmt.Println(err.Error())
		t.Fail()
	}
	dir2, err := ioutil.TempDir("/tmp/", "decoy2")
	if err != nil {
		t.Fatal(err)
	}

	var testDecoys1 = []*pb.TLSDecoySpec{
		pb.InitTLSDecoySpec("4.8.15.16", "ericw.us"),
		pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah"),
	}

	var testDecoys2 = []*pb.TLSDecoySpec{
		pb.InitTLSDecoySpec("0.1.2.3", "whatever.cn"),
		pb.InitTLSDecoySpec("255.254.253.252", "particular.ir"),
		pb.InitTLSDecoySpec("11.22.33.44", "what.is.up"),
		pb.InitTLSDecoySpec("8.255.255.8", "heh.meh"),
	}

	AssetsSetDir(dir1)
	err = Assets().SetDecoys(testDecoys1)
	if err != nil {
		t.Fatal(err)
	}
	if !Assets().IsDecoyInList(pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah")) {
		t.Fatal("Decoy 19.21.23.42(blahblahbl.ah) is NOT in Decoy List!")
	}
	AssetsSetDir(dir2)
	err = Assets().SetDecoys(testDecoys2)
	if err != nil {
		t.Fatal(err)
	}
	if Assets().IsDecoyInList(pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah")) {
		t.Fatal("Decoy 19.21.23.42(blahblahbl.ah) is in Decoy List!")
	}
	if !Assets().IsDecoyInList(pb.InitTLSDecoySpec("11.22.33.44", "what.is.up")) {
		t.Fatal("Decoy 11.22.33.44(what.is.up) is NOT in Decoy List!")
	}

	decoyInList := func(d *pb.TLSDecoySpec, decoyList []*pb.TLSDecoySpec) bool {
		for _, elem := range decoyList {
			if proto.Equal(elem, d) {
				return true
			}
		}
		return false
	}

	for i := 0; i < 10; i++ {
		_sni, addr := Assets().GetDecoyAddress()
		hostAddr, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal("Corrupted addr:", addr, ". Error:", err.Error())
		}
		decoyServ := pb.InitTLSDecoySpec(hostAddr, _sni)
		if !decoyInList(decoyServ, Assets().config.DecoyList.TlsDecoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().config.DecoyList.TlsDecoys)
			t.Fail()
		}
	}
	AssetsSetDir(dir1)

	if !Assets().IsDecoyInList(pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah")) {
		t.Fatal("Decoy 19.21.23.42(blahblahbl.ah) is NOT in Decoy List!")
	}
	if Assets().IsDecoyInList(pb.InitTLSDecoySpec("11.22.33.44", "what.is.up")) {
		t.Fatal("Decoy 11.22.33.44(what.is.up) is in Decoy List!")
	}
	for i := 0; i < 10; i++ {
		_sni, addr := Assets().GetDecoyAddress()
		hostAddr, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal("Corrupted addr:", addr, ". Error:", err.Error())
		}
		decoyServ := pb.InitTLSDecoySpec(hostAddr, _sni)
		if !decoyInList(decoyServ, Assets().config.DecoyList.TlsDecoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().config.DecoyList.TlsDecoys)
			t.Fail()
		}
	}
	os.Remove(path.Join(dir1, Assets().filenameClientConf))
	os.Remove(path.Join(dir2, Assets().filenameClientConf))
	os.Remove(dir1)
	os.Remove(dir2)
	AssetsSetDir(oldpath)
}

func TestAssets_Pubkey(t *testing.T) {
	var b bytes.Buffer
	logHolder := bufio.NewWriter(&b)
	oldLoggerOut := Logger().Out
	Logger().Out = logHolder
	defer func() {
		Logger().Out = oldLoggerOut
		if t.Failed() {
			logHolder.Flush()
			fmt.Printf("TapDance log was:\n%s\n", b.String())
		}
	}()
	initPubKey := func(defaultKey []byte) *pb.PubKey {
		defualtKeyType := pb.KeyType_AES_GCM_128
		return &pb.PubKey{Key: defaultKey, Type: &defualtKeyType}
	}

	oldpath := Assets().path
	Assets().saveClientConf()
	dir1, err := ioutil.TempDir("/tmp/", "pubkey1")
	if err != nil {
		t.Fatal(err)
	}
	dir2, err := ioutil.TempDir("/tmp/", "pubkey2")
	if err != nil {
		t.Fatal(err)
	}

	var pubkey1 = initPubKey([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
		27, 28, 29, 30, 31})
	var pubkey2 = initPubKey([]byte{200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
		212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
		227, 228, 229, 230, 231})

	AssetsSetDir(dir1)
	err = Assets().SetPubkey(pubkey1)
	if err != nil {
		t.Fatal(err)
	}
	AssetsSetDir(dir2)
	err = Assets().SetPubkey(pubkey2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Assets().config.DefaultPubkey.Key[:], pubkey2.Key[:]) {
		fmt.Println("Pubkeys are not equal!")
		fmt.Println("Assets().stationPubkey:", Assets().config.DefaultPubkey.Key[:])
		fmt.Println("pubkey2:", pubkey2)
		t.Fail()
	}

	AssetsSetDir(dir1)
	if !bytes.Equal(Assets().config.DefaultPubkey.Key[:], pubkey1.Key[:]) {
		fmt.Println("Pubkeys are not equal!")
		fmt.Println("Assets().stationPubkey:", Assets().config.DefaultPubkey.Key[:])
		fmt.Println("pubkey1:", pubkey1)
		t.Fail()
	}
	// os.Remove(path.Join(dir1, Assets().filenameStationPubkey))
	// os.Remove(path.Join(dir2, Assets().filenameStationPubkey))
	os.Remove(dir1)
	os.Remove(dir2)
	AssetsSetDir(oldpath)
}

func TestAssetsCacheing(t *testing.T) {
	p4 := net.ParseIP("1.2.3.4")
	reg := &ConjureReg{
		phantom4:  &p4,
		v6Support: both,
		// timeout: 2 seconds from now
	}

	err := Assets().CacheRegistration(reg)
	if err != nil {
		t.Fatalf("CacheRegistration returned error: %v", err)
	}

	reg = Assets().TryGetCachedRegistration()
	if reg == nil {
		t.Fatalf("Was unable to retrieve cached registration")
	}

	time.Sleep(time.Duration(4) * time.Second)

	reg = Assets().TryGetCachedRegistration()
	if reg != nil {
		t.Fatalf("Shouldn't have been able to retrieve cached registration after timeout.")
	}
}

/*
TODO Plan:
	- Add timeout tracking to ConjureReg
	- Add preferred status to Conjurereg
	- Modify ConjureReg To track stats in a meaningful way across connections
		* track updates to stats and registration state.
	- Add Some struct to the ClientConf Protobuf to track Cached Registrations

	- Add TryGetCachedRegistration to Dialer
	- Add CacheRegistration to Dialer

	- Expand tests

	- track registrations for longer lifetimes on station, and in the detector
	- generate registrations with longer lifetimes.


Questions:
-> HOW DO CLIENTS KNOW HOW LONG TO CACHE REGISTRATIONS FOR???????
    * Just set some automatic default for now that is hardcoded on the station
    and client independently. (i.e. both set a day for now)

	* Bidirectional registration that sends the value for timeout from the stations
	eventually
*/
