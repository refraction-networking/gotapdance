// Package tdproxy implements TapdanceProxy, which can ListenAndServe() on a given port,
// so you can use it as a SOCKS or HTTP proxy elsewhere.
package tdproxy

import (
	"github.com/sergeyfrolov/gotapdance/tapdance"
	"net"
	"strconv"
	"sync"
	"time"
)

var Logger = tapdance.Logger()

const (
	ProxyStateInitialized = "Initialized"
	ProxyStateListening   = "Listening"
	ProxyStateStopped     = "Stopped"
	ProxyStateError       = "Error"
)

// TODO: consider implementing https://golang.org/pkg/net/#Listener or other default interface
type TapDanceProxy struct {
	State string

	listener net.Listener

	listenPort int

	countTunnels tapdance.CounterUint64

	// statistics
	notPickedUp      tapdance.CounterUint64
	timedOut         tapdance.CounterUint64
	closedGracefully tapdance.CounterUint64
	unexpectedError  tapdance.CounterUint64

	connections struct {
		sync.RWMutex
		m map[uint64]*tapDanceFlow
	}

	statsTicker *time.Ticker

	stop bool
}

func NewTapDanceProxy(listenPort int) *TapDanceProxy {
	//Logger.Level = logrus.DebugLevel
	proxy := new(TapDanceProxy)
	proxy.listenPort = listenPort

	proxy.connections.m = make(map[uint64]*tapDanceFlow)
	proxy.State = ProxyStateInitialized

	Logger.Infof("Successfully initialized new Tapdance Proxy")
	Logger.Debugf("%#v\n", proxy)

	return proxy
}

func (proxy *TapDanceProxy) statsHelper() error {
	proxy.statsTicker = time.NewTicker(time.Second * time.Duration(60))
	for range proxy.statsTicker.C {
		Logger.Infof(proxy.GetStatistics())
	}
	return nil
}

func (proxy *TapDanceProxy) ListenAndServe() error {
	var err error
	listenAddress := "127.0.0.1:" + strconv.Itoa(proxy.listenPort)

	proxy.State = ProxyStateListening
	proxy.stop = false
	if proxy.listener, err = net.Listen("tcp", listenAddress); err != nil {
		proxy.State = ProxyStateError
		return err
	}
	Logger.Infof("Accepting connections at port " + strconv.Itoa(proxy.listenPort))
	go proxy.statsHelper()

	for !proxy.stop {
		if conn, err := proxy.listener.Accept(); err == nil {
			go proxy.handleUserConn(conn)
		} else {
			if proxy.stop {
				proxy.State = ProxyStateStopped
				err = nil
			} else {
				proxy.State = ProxyStateError
			}
			return err
		}
	}
	proxy.State = ProxyStateStopped
	return nil
}

func (proxy *TapDanceProxy) Stop() error {
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

func (proxy *TapDanceProxy) handleUserConn(userConn net.Conn) {
	tdState := proxy.addFlow(&userConn)
	defer func() {
		proxy.connections.Lock()
		delete(proxy.connections.m, tdState.id)
		proxy.connections.Unlock()
	}()

	// Initial request is not lost, because we still haven't read anything from client socket
	// So we just start Redirecting (client socket) <-> (server socket)
	if err := tdState.redirect(); err != nil {
		Logger.Errorf("[Session " + strconv.FormatUint(uint64(tdState.id), 10) +
			"] Shut down with error: " + err.Error())
	} else {
		Logger.Infof("[Session " + strconv.FormatUint(uint64(tdState.id), 10) +
			"] Closed gracefully.")
	}
	return
}

func (proxy *TapDanceProxy) GetStatistics() (statistics string) {
	statistics = "Sessions total: " +
		strconv.FormatUint(uint64(proxy.countTunnels.Get()), 10)
	statistics += ". Not picked up: " +
		strconv.FormatUint(uint64(proxy.notPickedUp.Get()), 10)
	statistics += ". Timed out: " +
		strconv.FormatUint(uint64(proxy.timedOut.Get()), 10)
	statistics += ". Unexpected error: " +
		strconv.FormatUint(uint64(proxy.unexpectedError.Get()), 10)
	statistics += ". Graceful close: " +
		strconv.FormatUint(uint64(proxy.closedGracefully.Get()), 10)
	return
}

func (proxy *TapDanceProxy) GetStats() (stats string) {
	stats = proxy.State + "\nPort: " + strconv.Itoa(proxy.listenPort) +
		"\nActive connections: " + strconv.Itoa(len(proxy.connections.m))
	return
}

func (proxy *TapDanceProxy) addFlow(userConn *net.Conn) (pTapdanceState *tapDanceFlow) {
	// Init connection state
	id := proxy.countTunnels.GetAndInc()

	pTapdanceState = makeTapDanceFlow(proxy, id, false)
	pTapdanceState.userConn = *userConn

	proxy.connections.Lock()
	proxy.connections.m[id] = pTapdanceState
	proxy.connections.Unlock()

	return
}
