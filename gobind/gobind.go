package proxybind

import (
	"bytes"
	"errors"
	"github.com/Sirupsen/logrus"
	"io"

	"github.com/SergeyFrolov/gotapdance/tapdance"
)

var td_proxy *tapdance.TapdanceProxy
var buffer bytes.Buffer
var b = make([]byte, 1048576)

func NewDecoyProxy(listenPort int) (err error) {

	tapdance.Logger.Out = &buffer
	tapdance.Logger.Level = logrus.InfoLevel
	tapdance.Logger.Formatter = new(logrus.JSONFormatter)
	td_proxy = tapdance.NewTapdanceProxy(listenPort)
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
		err = td_proxy.Listen()
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
		if td_proxy.State == tapdance.TD_LISTENING {
			listening = true
		} else {
			listening = false
		}
	}
	return
}
