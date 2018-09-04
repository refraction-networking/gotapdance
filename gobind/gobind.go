package gobind

import (
	"bytes"
	"errors"
	"github.com/sirupsen/logrus"
	"io"

	"github.com/sergeyfrolov/gotapdance/tapdance"
	"github.com/sergeyfrolov/gotapdance/tdproxy"
)

var td_proxy *tdproxy.TapDanceProxy
var buffer bytes.Buffer
var b = make([]byte, 1048576)

func NewDecoyProxy(listenPort int) (err error) {

	tapdance.Logger().Out = &buffer
	tapdance.Logger().Level = logrus.InfoLevel
	tapdance.Logger().Formatter = new(logrus.JSONFormatter)
	td_proxy = tdproxy.NewTapDanceProxy(listenPort)
	if td_proxy == nil {
		err = errors.New("Unable to initialize Proxy")
	}
	return
}

func GetLog() (out string) {
	n, err := buffer.Read(b)
	if err == io.EOF {
		out = ""
	} else if err != nil {
		out = err.Error()
	} else {
		out = string(b[:n])
	}
	return
}

func Listen() (err error) {
	if td_proxy == nil {
		err = errors.New("Proxy is not initialized")
	} else {
		err = td_proxy.ListenAndServe()
	}
	return
}

func Stop() (err error) {
	if td_proxy == nil {
		err = errors.New("Proxy is not initialized")
	} else {
		err = td_proxy.Stop()
	}
	return
}

func GetStats() (stats string) {
	if td_proxy == nil {
		stats = "State: Not initialized."
	} else {
		stats = "State: " + td_proxy.GetStats()
	}
	return
}

func IsListening() (listening bool) {
	if td_proxy == nil {
		listening = false
	} else {
		if td_proxy.State == tdproxy.ProxyStateListening {
			listening = true
		} else {
			listening = false
		}
	}
	return
}
