package tapdance

import (
	"encoding/binary"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/zmap/zcrypto/x509"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"sync"
)

type assets struct {
	sync.RWMutex
	once sync.Once
	path string

	config ClientConf

	roots *x509.CertPool

	filenameStationPubkey string
	filenameRoots         string
	filenameClientConf    string
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
		tlsDecoy := TLSDecoySpec{Hostname: &sni,
			Ipv4Addr: &ipUint32}
		return &tlsDecoy
	}

	var defaultDecoys = []*TLSDecoySpec{
		initTLSDecoySpec("192.122.190.104", "tapdance1.freeaeskey.xyz"),
	}

	defaultKey := []byte{189, 193, 226, 121, 87, 194, 76, 106, 81, 218,
		245, 186, 4, 222, 249, 237, 96, 101, 77, 161, 183, 123, 63,
		216, 18, 104, 111, 181, 75, 208, 232, 12}
	defualtKeyType := KeyType_AES_GCM_128
	defaultPubKey := PubKey{Key: defaultKey, Type: &defualtKeyType}
	defaultGeneration := uint32(0)
	defaultDecoyList := DecoyList{TlsDecoys: defaultDecoys}
	defaultClientConf := ClientConf{DecoyList: &defaultDecoyList,
		DefaultPubkey: &defaultPubKey,
		Generation:    &defaultGeneration}

	assetsOnce.Do(func() {
		assetsInstance = &assets{
			path:                  "./assets/",
			config:                defaultClientConf,
			filenameRoots:         "roots",
			filenameClientConf:    "ClientConf",
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

	readClientConf := func(filename string) error {
		buf, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		clientConf := ClientConf{}
		err = proto.Unmarshal(buf, &clientConf)
		if err != nil {
			return err
		}
		a.config = clientConf
		return nil
	}

	readPubkey := func(filename string) error {
		staionPubkey, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}
		if len(staionPubkey) != 32 {
			return errors.New("Unexpected keyfile length! Expected: 32. Got: " +
				strconv.Itoa(len(staionPubkey)))
		}
		copy(a.config.DefaultPubkey.Key[:], staionPubkey[0:32])
		return nil
	}

	var err error
	Logger.Infoln("Assets: reading from folder " + a.path)

	rootsFilename := path.Join(a.path, a.filenameRoots)
	err = readRoots(rootsFilename)
	if err != nil {
		Logger.Warningln("Failed to read root ca file: " + err.Error())
	} else {
		Logger.Infoln("X.509 root CAs succesfully read from " + rootsFilename)
	}

	clientConfFilename := path.Join(a.path, a.filenameClientConf)
	err = readClientConf(clientConfFilename)
	if err != nil {
		Logger.Warningln("Failed to read ClientConf file: " + err.Error())
	} else {
		Logger.Infoln("Client config succesfully read from " + clientConfFilename)
	}

	pubkeyFilename := path.Join(a.path, a.filenameStationPubkey)
	err = readPubkey(pubkeyFilename)
	if err != nil {
		Logger.Warningln("Failed to read pubkey file: " + err.Error())
	} else {
		Logger.Infoln("Pubkey succesfully read from " + pubkeyFilename)
	}
}

// gets randomDecoyAddress. sni stands for subject name indication.
// addr is in format ipv4:port
func (a *assets) GetDecoyAddress() (sni string, addr string) {
	a.RLock()
	defer a.RUnlock()

	decoys := a.config.DecoyList.TlsDecoys
	decoyIndex := getRandInt(0, len(decoys)-1)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, decoys[decoyIndex].GetIpv4Addr())
	// TODO: what checks need to be done, and what's guaranteed?
	addr = ip.To4().String() + ":443"
	sni = decoys[decoyIndex].GetHostname()
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
	copy(pKey[:], a.config.DefaultPubkey.Key[:])
	return &pKey
}

func (a *assets) GetGeneration() uint32 {
	a.RLock()
	defer a.RUnlock()

	return a.config.GetGeneration()
}

func (a *assets) SetGeneration(gen uint32) (err error) {
	a.Lock()
	defer a.Unlock()

	copyGen := gen
	a.config.Generation = &copyGen
	err = a.saveClientConf()
	return
}

// Set Public key in persistent way (e.g. store to disk)
func (a *assets) SetPubkey(pubkey PubKey) (err error) {
	a.Lock()
	defer a.Unlock()

	copyPubkey := pubkey
	a.config.DefaultPubkey = &copyPubkey
	err = a.saveClientConf()
	return
}

func (a *assets) SetClientConf(conf *ClientConf) (err error) {
	a.Lock()
	defer a.Unlock()

	a.config = *conf
	err = a.saveClientConf()
	return
}

// Set decoys in persistent way (e.g. store to disk)
func (a *assets) SetDecoys(decoys []*TLSDecoySpec) (err error) {
	a.Lock()
	defer a.Unlock()

	a.config.DecoyList.TlsDecoys = decoys
	err = a.saveClientConf()
	return
}

func (a *assets) saveClientConf() error {
	buf, err := proto.Marshal(&a.config)
	if err != nil {
		return err
	}
	filename := path.Join(a.path, a.filenameClientConf)
	tmpFilename := path.Join(a.path, "."+a.filenameClientConf+".tmp")
	err = ioutil.WriteFile(tmpFilename, buf[:], 0644)
	if err != nil {
		return err
	}

	return os.Rename(tmpFilename, filename)
}
