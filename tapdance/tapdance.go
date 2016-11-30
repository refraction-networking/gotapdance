package tapdance

import (
	"github.com/zmap/zgrab/ztools/x509"
	"net"

	"strconv"

	"io/ioutil"
	"sync"

	"os"
	"github.com/Sirupsen/logrus"
)

var Logger = logrus.New()

const initial_tag = "SPTELEX"

const (
	TD_INITIALIZED = "Initialized"
	TD_LISTENING = "Listening"
	TD_STOPPED = "Stopped"
	TD_ERROR = "Error"
)

// global object
type TapdanceProxy struct {
	State string
			       /* crypto param files */
	ca_list       string
	dh_file       string

	keyfile       string   // public key filename
	stationPubkey [32]byte // contents of keyfile
	roots         *x509.CertPool

	listener      net.Listener

	listenPort    int

	countTunnels  counter_uint

	connections   struct {
		sync.RWMutex
		m map[uint]*TDConnState}

	stop          bool
}

func NewTapdanceProxyByKeypath(listenPort int, keyPath string) *TapdanceProxy {
	keyfile := keyPath + "pubkey.dev"
	ca_list := keyPath + "root.pem"

	sliceStaionPubkey, err := ioutil.ReadFile(keyfile)
	if err != nil {
		Logger.Fatalf("Could not read keyfile: ", err.Error())
		os.Exit(1)
	}
	sliceStaionRootPem, err := ioutil.ReadFile(ca_list)
	if err != nil {
		Logger.Fatalf("Could not read root ca file: ", err.Error())
		os.Exit(2)
	}

	proxy := NewTapdanceProxyByKeys(listenPort, sliceStaionPubkey, sliceStaionRootPem)

	return proxy
}

func NewTapdanceProxyByKeys(listenPort int, staionPubkey []byte, staionRootpem []byte) *TapdanceProxy {
	Logger.Level = logrus.DebugLevel
	Logger.Formatter = new(MyFormatter)
	proxy := new(TapdanceProxy)
	proxy.listenPort = listenPort

	copy(proxy.stationPubkey[:], staionPubkey[0:32])

	proxy.roots = x509.NewCertPool()
	ok := proxy.roots.AppendCertsFromPEM(staionRootpem)
	if !ok {
		proxy.State = TD_ERROR
		Logger.Fatalf("Failed to parse root certificate")
		os.Exit(3) // TODO: print mobile-friendly error
	}

	proxy.connections.m = make(map[uint]*TDConnState)
	proxy.State = TD_INITIALIZED

	Logger.Infof("Succesfully initialized new Tapdance Proxy." +
		" Please press \"Launch\" to start accepting connections.")
	Logger.Debug(*proxy)

	return proxy
}

func (proxy *TapdanceProxy) Listen() error {
	var err error
	listenAddress := "0.0.0.0:" + strconv.Itoa(proxy.listenPort)

	proxy.State = TD_LISTENING
	proxy.stop = false
	if proxy.listener, err = net.Listen("tcp", listenAddress); err != nil {
		Logger.Infof("Failed listening at port " + strconv.Itoa(proxy.listenPort) +
			". Error: " + err.Error())
		proxy.State = TD_ERROR
		return err
	}
	Logger.Infof("Accepting connections at port " + strconv.Itoa(proxy.listenPort))

	for !proxy.stop {
		if conn, err := proxy.listener.Accept(); err == nil {
			go proxy.handleUserConn(conn)
		} else {
			if proxy.stop {
				proxy.State = TD_STOPPED
				err = nil
			} else {
				proxy.State = TD_ERROR
			}
			return err
		}
	}
	proxy.State = TD_STOPPED
	return nil
}

func (proxy *TapdanceProxy) Stop() error {
	proxy.stop = true
	proxy.listener.Close()
	// TODO: clean up goroutines
	return nil
}

func (proxy *TapdanceProxy) handleUserConn(userConn net.Conn) {
	tdState, err := proxy.NewConnectionToTDStation(&userConn)
	defer func() {
		proxy.connections.Lock()
		delete(proxy.connections.m, tdState.id)
		proxy.connections.Unlock()
	}()
	if err != nil {
		userConn.Close()
		//Logger.Errorf("Establishing initial connection to decoy server failed with " + err.Error())
		return
	}

	// Initial request is not lost, because we still haven't read anything from client socket
	// So we just start Redirecting (client socket) <-> (server socket)
	if err = tdState.Redirect(); err != nil {
		// TODO: errors are printed inside Redirect()
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdState.id), 10) +
			"] Shut down with error: " + err.Error())
	} else {
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdState.id), 10) +
			"] Closed gracefully.")
	}
	return
}

func (proxy *TapdanceProxy) GetStats() (stats string) {
	stats = proxy.State + "\nPort: " + strconv.Itoa(proxy.listenPort) +
		"\nActive connections: " + strconv.Itoa(len(proxy.connections.m))
	return
}

func (proxy *TapdanceProxy) NewConnectionToTDStation(userConn *net.Conn) (pTapdanceState *TDConnState, err error) {
	// Init connection state
	id := proxy.countTunnels.inc() // TODO: wtf?

	pTapdanceState = NewTapdanceState(proxy, id)
	pTapdanceState.userConn = *userConn

	proxy.connections.Lock()
	proxy.connections.m[id] = pTapdanceState
	proxy.connections.Unlock()

	return
}
