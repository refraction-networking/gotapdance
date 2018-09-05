package tdproxy

import (
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"io/ioutil"
	"os"
	"testing"

	"crypto/tls"
	"fmt"
	"golang.org/x/net/websocket"
	"math/rand"
	"time"

	"io"
)

func setupTestAssets() error {
	tmpDir, err := ioutil.TempDir("/tmp/", "td-test-")
	if err != nil {
		return err
	}
	tapdance.AssetsSetDir(tmpDir)
	// make sure station won't send new ClientConf
	err = tapdance.Assets().SetGeneration(100500)
	if err != nil {
		return err
	}

	// use testing public key
	keyType := pb.KeyType_AES_GCM_128
	stationTestPubkey, err := ioutil.ReadFile("../assets/station_pubkey_test")
	if err != nil {
		return err
	}

	pubKey := pb.PubKey{
		Key:  stationTestPubkey,
		Type: &keyType,
	}
	if err != nil {
		return err
	}
	tapdance.Assets().SetPubkey(pubKey)

	// use correct decoy
	tapdance1Decoy := pb.InitTLSDecoySpec("192.122.190.104", "tapdance1.freeaeskey.xyz")
	err = tapdance.Assets().SetDecoys([]*pb.TLSDecoySpec{tapdance1Decoy})
	if err != nil {
		return err
	}
	return nil
}

func TestMain(m *testing.M) {
	err := setupTestAssets()
	if err != nil {
		panic(err)
	}
	retCode := m.Run()
	os.Exit(retCode)
}

func TestSendSeq(t *testing.T) {
	conn, err := tapdance.Dial("tcp", "sfrolov.io:443")
	if err != nil {
		t.Error(err)
		return
	}
	conf, err := websocket.NewConfig("wss://sfrolov.io/echo", "http://localhost/")
	if err != nil {
		t.Error(err)
		return
	}
	wsConn, err := websocket.NewClient(conf,
		tls.Client(conn, &tls.Config{ServerName: "sfrolov.io"}))
	//err = sendseq.SendSeq(,
	//	tls.Client(conn, &tls.Config{ServerName: "sfrolov.io"}))
	if err != nil {
		t.Error(err)
		return
	}

	rand.Seed(time.Now().UTC().Unix())

	randString := func(n int) []byte {
		const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rand.Intn(len(alphabet))]
		}
		return b
	}

	const repetitions = 5
	for ii := 0; ii < repetitions; ii++ {
		bytesOut := randString(20000 + rand.Intn(40000))
		bytesIn := make([]byte, len(bytesOut))
		_, err = wsConn.Write(bytesOut)
		if err != nil {
			t.Error(err)
			return
		}

		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(10)))
		wsConn.SetDeadline(time.Now().Add(time.Second * time.Duration(10)))
		_, err = io.ReadFull(wsConn, bytesIn)
		if err != nil {
			t.Error(err)
		}

		for i := range bytesOut {
			if bytesIn[i] != bytesOut[i] {
				fmt.Println("bytesIn: ", bytesIn)
				fmt.Println("bytesOut: ", bytesOut)
				t.Errorf("received buffer differs from sent at position %v", i)
			}
		}
	}
}
