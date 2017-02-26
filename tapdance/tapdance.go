package tapdance

import (
	"github.com/Sirupsen/logrus"
	"net"
	"strconv"
	"sync"
	"time"
)

var Logger = logrus.New()

var td_station_pubkey = [32]byte{211, 127, 10, 139, 150, 180, 97, 15, 56, 188, 7, 155, 7, 102, 41, 34,
	70, 194, 210, 170, 50, 53, 234, 49, 42, 240, 41, 27, 91, 38, 247, 67}

const initial_tag = "SPTELEX"
const (
	TD_INITIALIZED = "Initialized"
	TD_LISTENING   = "Listening"
	TD_STOPPED     = "Stopped"
	TD_ERROR       = "Error"
)

// global object
type TapdanceProxy struct {
	State string

	stationPubkey [32]byte // contents of keyfile

	listener net.Listener

	listenPort int

	countTunnels counter_uint64

	// statistics
	notPickedUp      counter_uint64
	timedOut         counter_uint64
	closedGracefully counter_uint64
	unexpectedError  counter_uint64

	connections struct {
		sync.RWMutex
		m map[uint64]*TapDanceFlow
	}

	statsTicker *time.Ticker

	stop bool
}

func NewTapdanceProxy(listenPort int) *TapdanceProxy {
	//Logger.Level = logrus.DebugLevel
	Logger.Level = logrus.InfoLevel
	Logger.Formatter = new(MyFormatter)
	proxy := new(TapdanceProxy)
	proxy.listenPort = listenPort
	// TODO: do I need it?
	copy(proxy.stationPubkey[:], td_station_pubkey[0:32])

	proxy.connections.m = make(map[uint64]*TapDanceFlow)
	proxy.State = TD_INITIALIZED

	Logger.Infof("Succesfully initialized new Tapdance Proxy." +
		" Please press \"Launch\" to start accepting connections.")
	Logger.Debug(*proxy)

	return proxy
}

func (proxy *TapdanceProxy) statsHelper() error {
	proxy.statsTicker = time.NewTicker(time.Second * time.Duration(60))
	for range proxy.statsTicker.C {
		Logger.Infof(proxy.GetStatistics())
	}
	return nil
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
	go proxy.statsHelper()

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
	proxy.connections.Lock()
	for _, tdState := range proxy.connections.m {
		tdState.servConn.Close()
	}
	proxy.connections.Unlock()
	proxy.statsTicker.Stop()
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
		Logger.Errorf("[Flow " + strconv.FormatUint(uint64(tdState.id), 10) +
			"] Shut down with error: " + err.Error())
	} else {
		Logger.Infof("[Flow " + strconv.FormatUint(uint64(tdState.id), 10) +
			"] Closed gracefully.")
	}
	return
}

func (proxy *TapdanceProxy) GetStatistics() (statistics string) {
	statistics = "Flows total: " +
		strconv.FormatUint(uint64(proxy.countTunnels.get()), 10)
	statistics += ". Not picked up: " +
		strconv.FormatUint(uint64(proxy.notPickedUp.get()), 10)
	statistics += ". Timed out: " +
		strconv.FormatUint(uint64(proxy.timedOut.get()), 10)
	statistics += ". Unexpected error: " +
		strconv.FormatUint(uint64(proxy.unexpectedError.get()), 10)
	statistics += ". Graceful close: " +
		strconv.FormatUint(uint64(proxy.closedGracefully.get()), 10)
	return
}

func (proxy *TapdanceProxy) GetStats() (stats string) {
	stats = proxy.State + "\nPort: " + strconv.Itoa(proxy.listenPort) +
		"\nActive connections: " + strconv.Itoa(len(proxy.connections.m))
	return
}

func (proxy *TapdanceProxy) NewConnectionToTDStation(userConn *net.Conn) (pTapdanceState *TapDanceFlow, err error) {
	// Init connection state
	id := proxy.countTunnels.inc()

	pTapdanceState = NewTapDanceFlow(proxy, id)
	pTapdanceState.userConn = *userConn

	proxy.connections.Lock()
	proxy.connections.m[id] = pTapdanceState
	proxy.connections.Unlock()

	return
}
