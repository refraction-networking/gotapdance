package tapdance

import (
	"github.com/pkg/errors"
	"github.com/zmap/zcrypto/x509"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"sync"
	"net"
	"encoding/binary"
	"github.com/golang/protobuf/proto"
)

type assets struct {
	sync.RWMutex
	once   sync.Once
	path   string

	decoyUpd DecoysUpdate

	roots         *x509.CertPool

	filenameStationPubkey string
	filenameRoots         string
	filenameDecoys        string
}

var assetsInstance *assets
var assetsOnce sync.Once

// Path is expected (but doesn't have) to have several files
// 1) "decoys" that has a list in following format:
//       ip1:SNI1
//       ip2:SNI2
// 2) "station_pubkey" contains TapDance station Public Key
// 3) "roots" contains x509 roots
func Assets() *assets {
	initTLSDecoySpec := func(ip string, sni string) *TLSDecoySpec {
		ipUint32 := binary.BigEndian.Uint32(net.ParseIP(ip).To4())
		Logger.Errorln("ipUint32", ipUint32)
		tlsDecoy := TLSDecoySpec{Hostname: &sni,
			Ipv4Addr: &ipUint32}
		return &tlsDecoy
	}

	var defaultDecoys = []*TLSDecoySpec{
		initTLSDecoySpec("192.122.190.104", "tapdance1.freeaeskey.xyz"),
		initTLSDecoySpec("192.122.190.105", "tapdance2.freeaeskey.xyz"),
	}
	aes_gcm_128 := KeyType_AES_GCM_128
	defaultPubkey := PubKey{Key: []byte{211, 127, 10, 139, 150, 180, 97,
		15, 56, 188, 7, 155, 7, 102, 41, 34, 70, 194, 210, 170, 50,
		53, 234, 49, 42, 240, 41, 27, 91, 38, 247, 67},
		Type: &aes_gcm_128}
	defaultGeneration := uint32(0)

	defaultDecoyUpd := DecoysUpdate{TlsDecoys: defaultDecoys,
		DefaultPubkey: &defaultPubkey,
		Generation: &defaultGeneration}

	assetsOnce.Do(func() {
		assetsInstance = &assets{
			path:   "./assets/",
			decoyUpd: defaultDecoyUpd,
			filenameRoots:         "roots",
			filenameDecoys:        "decoys",
			filenameStationPubkey: "station_pubkey",
		}
		assetsInstance.readConfigs()
	})
	return assetsInstance
}

func (a *assets) GetAssetsDir() string {
	a.RLock()
	defer a.RUnlock()
	return a.path
}

func (a *assets) SetAssetsDir(path string) {
	a.Lock()
	defer a.Unlock()
	a.path = path
	a.readConfigs()
	return
}

func (a *assets) readConfigs() {

	readPubkey := func(filename string) error {
		staionPubkey, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		if len(staionPubkey) != 32 {
			return errors.New("Unexpected keyfile length! Expected: 32. Got: " +
				strconv.Itoa(len(staionPubkey)))
		}
		copy(a.decoyUpd.DefaultPubkey.Key, staionPubkey[0:32])
		return nil
	}

	readRoots := func(filename string) error {
		rootCerts, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(rootCerts)
		if !ok {
			return errors.New("Failed to parse root certificates")
		} else {
			a.roots = roots
		}
		return nil
	}

	readDecoys := func(filename string) error {
		buf, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		err = proto.Unmarshal(buf, &a.decoyUpd)
		return err
	}

	var err error
	Logger.Infoln("Assets: reading from folder " + a.path)

	pubkeyFilename := path.Join(a.path, a.filenameStationPubkey)
	err = readPubkey(pubkeyFilename)
	if err != nil {
		Logger.Warningln("Failed to read keyfile: " + err.Error())
	} else {
		Logger.Infoln("Public key succesfully read from " + pubkeyFilename)
	}

	rootsFilename := path.Join(a.path, a.filenameRoots)
	err = readRoots(rootsFilename)
	if err != nil {
		Logger.Warningln("Failed to read root ca file: " + err.Error())
	} else {
		Logger.Infoln("X.509 root CAs succesfully read from " + rootsFilename)
	}

	decoyFilename := path.Join(a.path, a.filenameDecoys)
	err = readDecoys(decoyFilename)
	if err != nil {
		Logger.Warningln("Failed to read decoy file: " + err.Error())
	} else {
		Logger.Infoln("Decoys successfully read from " + decoyFilename)
	}
}

// gets randomDecoyAddress. sni stands for subject name indication.
// addr is in format ipv4:port
func (a *assets) GetDecoyAddress() (sni string, addr string) {
	a.RLock()
	defer a.RUnlock()

	decoyIndex := getRandInt(0, len(a.decoyUpd.TlsDecoys)-1)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, a.decoyUpd.TlsDecoys[decoyIndex].GetIpv4Addr())
	// TODO: what checks need to be done, and what's guaranteed?
	addr = ip.To4().String() + ":443"
	sni = a.decoyUpd.TlsDecoys[decoyIndex].GetHostname()
	return
}

func (a *assets) GetRoots() *x509.CertPool {
	a.RLock()
	defer a.RUnlock()

	return a.roots
}

func (a *assets) GetPubkey() *[32]byte {
	a.RLock()
	defer a.RUnlock()

	var pKey [32]byte
	copy(pKey[:], a.decoyUpd.DefaultPubkey.Key)
	return &pKey
}

func (a *assets) getDecoyListGeneration() uint32 {
	a.RLock()
	defer a.RUnlock()

	return a.decoyUpd.GetGeneration()
}


// Set Public key in persistent way (e.g. store to disk)
func (a *assets) SetPubkey(pubkey [32]byte) (err error) {
	a.Lock()
	defer a.Unlock()

	a.decoyUpd.DefaultPubkey.Key = pubkey[:]
	err = a.savePubkey()
	return
}

// Set decoys in persistent way (e.g. store to disk)
func (a *assets) SetDecoys(decoys []*TLSDecoySpec) (err error) {
	a.Lock()
	defer a.Unlock()

	a.decoyUpd.TlsDecoys = decoys
	err = a.saveDecoys()
	return
}

func (a *assets) saveDecoys() error {
	buf, err := proto.Marshal(&a.decoyUpd)
	if err != nil {
		return err
	}
	filename := path.Join(a.path, a.filenameDecoys)
	tmpFilename := path.Join(a.path, "." + a.filenameDecoys+".tmp")
	err = ioutil.WriteFile(tmpFilename, buf[:], 0644)
	if err != nil {
		return err
	}
	os.Rename(tmpFilename, filename)
	return nil
}

func (a *assets) savePubkey() error {
	filename := path.Join(a.path, a.filenameStationPubkey)
	tmpFilename := path.Join(a.path, "." + a.filenameStationPubkey+".tmp")
	err := ioutil.WriteFile(tmpFilename, a.decoyUpd.DefaultPubkey.Key[:], 0644)
	if err != nil {
		return err
	}
	os.Rename(tmpFilename, filename)
	return nil
}

/*
We probably don't need those functions.
If we do: how to marshall roots?

func (a *assets) setRoots() error {
}

func (a *assets) saveRoots() error {
	a.roots
}
*/
