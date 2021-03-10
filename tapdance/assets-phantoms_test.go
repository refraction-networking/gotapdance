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

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	ps "github.com/refraction-networking/gotapdance/tapdance/phantoms"
	"github.com/stretchr/testify/assert"
)

func TestAssetsPhantomsBasics(t *testing.T) {
	phantomSet := Assets().GetPhantomSubnets()
	assert.NotNil(t, phantomSet)
}

func TestAssetsPhantoms(t *testing.T) {
	var b bytes.Buffer
	logHolder := bufio.NewWriter(&b)
	oldLoggerOut := Logger().Out
	Logger().Out = logHolder
	defer func() {
		Logger().Out = oldLoggerOut
		if t.Failed() {
			// logHolder.Flush()
			// fmt.Printf("TapDance log was:\n%s\n", b.String())
		}
	}()
	oldpath := Assets().path

	dir1, err := ioutil.TempDir("/tmp/", "decoy1")
	if err != nil {
		t.Fatal(err)
	}

	var testPhantoms = ps.GetDefaultPhantomSubnets()

	AssetsSetDir(dir1)
	err = Assets().SetPhantomSubnets(testPhantoms)
	if err != nil {
		t.Fatal(err)
	}

	containsPhantom := func(d *pb.TLSDecoySpec, decoyList []*pb.TLSDecoySpec) bool {
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
		if !containsPhantom(decoyServ, Assets().config.DecoyList.TlsDecoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().config.DecoyList.TlsDecoys)
			t.Fail()
		}
	}
	AssetsSetDir(dir1)

	for i := 0; i < 10; i++ {
		_sni, addr := Assets().GetDecoyAddress()
		hostAddr, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal("Corrupted addr:", addr, ". Error:", err.Error())
		}
		decoyServ := pb.InitTLSDecoySpec(hostAddr, _sni)
		if !containsPhantom(decoyServ, Assets().config.DecoyList.TlsDecoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().config.DecoyList.TlsDecoys)
			t.Fail()
		}
	}
	os.Remove(path.Join(dir1, Assets().filenameClientConf))
	os.Remove(dir1)
	AssetsSetDir(oldpath)
}
