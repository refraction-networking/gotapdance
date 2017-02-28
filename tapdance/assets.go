package tapdance

import (
	"sync"
	"strconv"
	"github.com/zmap/zgrab/ztools/x509"
	"io/ioutil"
	"os"
	"sync/atomic"
)

type decoyServer struct {
	ip  string
	sni string
}

var defaultDecoys = []decoyServer{
	{ip: "192.122.190.104", sni: "tapdance1.freeaeskey.xyz"},
	{ip: "192.122.190.105", sni: "tapdance2.freeaeskey.xyz"},
}

type assets struct {
	sync.RWMutex
	path          string
	decoys        []decoyServer
	configWasRead int32
				      /* crypto param files */
	caList        string
	dhFile        string

	keyfile       string   // public key filename
	stationPubkey [32]byte // contents of keyfile
	roots         *x509.CertPool // TODO: roots
}

var td_station_pubkey = [32]byte{211, 127, 10, 139, 150, 180, 97, 15, 56, 188, 7, 155, 7, 102,
	41, 34, 70, 194, 210, 170, 50, 53, 234, 49, 42, 240, 41, 27, 91, 38, 247, 67}

// Path is expected to have several files
// "decoys" that has a list in following format:
//     ip1:SNI1
//     ip2:SNI2
// "roots"
var Assets = assets{
	path: ".",
	decoys: defaultDecoys,
	stationPubkey: [32]byte{211, 127, 10, 139, 150, 180, 97, 15, 56, 188, 7, 155, 7, 102,
	41, 34, 70, 194, 210, 170, 50, 53, 234, 49, 42, 240, 41, 27, 91, 38, 247, 67},
}

func (a *assets) getAssetsDir() string {
	a.RLock()
	defer a.RUnlock()
	return a.path
}

func (a *assets) setAssetsDir(path string) {
	a.Lock()
	defer a.Unlock()
	a.path = path
	atomic.StoreInt32(&a.configWasRead, 0)
	return
}

func (a *assets) readConfig() {
	a.Lock()
	defer a.Unlock() // lots of locks, but that happens just once
	keyfile := a.path + "pubkey.dev"
	ca_list := a.path + "root.pem"

	sliceStaionPubkey, err := ioutil.ReadFile(keyfile)
	if err != nil {
		Logger.Errorln("Could not read keyfile: " + err.Error())
	} else if len(sliceStaionPubkey) != 32 {
		Logger.Errorln("Unexpected keyfile length! Expected: 32. Got: " +
			strconv.Itoa(len(sliceStaionPubkey)))
	} else {
		copy(a.stationPubkey[:], sliceStaionPubkey[0:32])
	}

	sliceStaionRootPem, err := ioutil.ReadFile(ca_list)
	if err != nil {
		Logger.Errorln("Could not read root ca file: " + err.Error())
		os.Exit(2)
	} else {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(sliceStaionRootPem)
		if !ok {
			Logger.Errorln("Failed to parse root certificates")
		} else {
			a.roots = roots
		}
	}
}

// gets randomDecoyAddress. sni stands for subject name indication.
// addr is in format ipv4:port
func (a *assets) getDecoyAddress() (sni string, addr string) {
	a.RLock()
	defer a.RUnlock()
	if atomic.CompareAndSwapInt32(&a.configWasRead, 0, 1) {
		a.RUnlock()
		a.readConfig()
		a.RLock()
	}
	decoyIndex := getRandInt(0, len(a.decoys)-1)
	addr = a.decoys[decoyIndex].ip + ":" + strconv.Itoa(443)
	sni = a.decoys[decoyIndex].sni
	return
}