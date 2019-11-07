package tapdance

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/sirupsen/logrus"
)

// implements interface logrus.Formatter
type formatter struct {
}

func (f *formatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("[%s] %s\n", entry.Time.Format("15:04:05"), entry.Message)), nil
}

var logrusLogger *logrus.Logger
var initLoggerOnce sync.Once

// Logger is an access point for TapDance-wide logger
func Logger() *logrus.Logger {
	initLoggerOnce.Do(func() {
		logrusLogger = logrus.New()
		logrusLogger.Formatter = new(formatter)
		// logrusLogger.Level = logrus.InfoLevel
		logrusLogger.Level = logrus.DebugLevel

		// buildInfo const will be overwritten by CI with `sed` for test builds
		// if not overwritten -- this is a NO-OP
		const buildInfo = ""
		if len(buildInfo) > 0 {
			logrusLogger.Infof("Running gotapdance build %s", buildInfo)
		}
	})
	return logrusLogger
}

func StatsReporting(stats *pb.SessionStats) {
	socks_url, err := url.Parse("socks5://" + Assets().GetStatsSocksAddr())
	// Test socks5 proxy
	//socks_url, err := url.Parse("socks5://localhost:8080")
	fmt.Printf("Got %v as socks5 proxy\n", socks_url)
	if err != nil {
		Logger().Debugf("Could not parse socks addr %v: %v\n", Assets().GetStatsSocksAddr(), err)
		return
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(socks_url)}}

	data, err := proto.Marshal(stats)
	if err != nil {
		Logger().Debugf("Could not marshal stats protobuf: %v", err)
		return
	}

	// TODO setup stats endpoint
	client.Post("https://stats.refraction.network", "stats", bytes.NewReader(data))
	return
}
