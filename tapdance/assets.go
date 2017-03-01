package tapdance

import (
	"github.com/zmap/zgrab/ztools/x509"
	"io/ioutil"
	"strconv"
	"sync"
)

type decoyServer struct {
	ip  string
	sni string
}

var defaultDecoys = []decoyServer{
	{ip: "192.122.190.104", sni: "tapdance1.freeaeskey.xyz"},
	//{ip: "192.122.190.105", sni: "tapdance2.freeaeskey.xyz"},
}

type assets struct {
	sync.RWMutex
	once sync.Once
	path          string
	decoys        []decoyServer

	stationPubkey [32]byte
	roots         *x509.CertPool
}

var td_station_pubkey = [32]byte{211, 127, 10, 139, 150, 180, 97, 15, 56, 188, 7, 155, 7, 102,
	41, 34, 70, 194, 210, 170, 50, 53, 234, 49, 42, 240, 41, 27, 91, 38, 247, 67}


var assetsInstance *assets
var assetsOnce sync.Once

// Don't call this function, if you use non-standard path
func Assets() *assets {
	return AssetsByPath("./assets/")
}

// Path is expected (but doesn't have) to have several files
// 1) "decoys" that has a list in following format:
//       ip1:SNI1
//       ip2:SNI2
// 2) "station_pubkey" contains TapDance station Public Key
// 3) "roots" contains x509 roots
func AssetsByPath(path string) *assets {
	assetsOnce.Do(func() {
		assetsInstance = &assets{
			path:   path,
			decoys: defaultDecoys,
			stationPubkey: [32]byte{211, 127, 10, 139, 150, 180, 97, 15, 56, 188, 7,
				155, 7, 102, 41, 34, 70, 194, 210, 170, 50, 53, 234, 49, 42, 240,
				41, 27, 91, 38, 247, 67},
		}
		assetsInstance.readConfigs()
	})
	return assetsInstance
}

/*
TODO:
- SetDecoys
- readDecoys
- saveDecoys
- SetPubkey
- savePubkey
- saveRoots
- SetRoots
 */

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
	keyfile := a.path + "station_pubkey"
	caList := a.path + "roots"
	//decoyList := a.path + "decoys"

	sliceStaionPubkey, err := ioutil.ReadFile(keyfile)
	if err != nil {
		Logger.Errorln("Could not read keyfile: " + err.Error())
	} else if len(sliceStaionPubkey) != 32 {
		Logger.Errorln("Unexpected keyfile length! Expected: 32. Got: " +
			strconv.Itoa(len(sliceStaionPubkey)))
	} else {
		copy(a.stationPubkey[:], sliceStaionPubkey[0:32])
	}

	sliceStaionRootPem, err := ioutil.ReadFile(caList)
	if err != nil {
		Logger.Errorln("Could not read root ca file: " + err.Error())
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
func (a *assets) GetDecoyAddress() (sni string, addr string) {
	a.RLock()
	defer a.RUnlock()

	decoyIndex := getRandInt(0, len(a.decoys)-1)
	addr = a.decoys[decoyIndex].ip + ":" + strconv.Itoa(443)
	sni = a.decoys[decoyIndex].sni
	return
}

func (a *assets) GetRoots() (*x509.CertPool) {
	a.RLock()
	defer a.RUnlock()

	return a.roots
}

func (a *assets) GetPubkey() (pubkey [32]byte) {
	a.RLock()
	defer a.RUnlock()

	return a.stationPubkey
}
