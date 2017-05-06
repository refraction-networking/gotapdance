package tapdance

import (
	"github.com/Sirupsen/logrus"
	"sync"
)

// implements interface logrus.Formatter
type formatter struct {
}

func (f *formatter) Format(entry *logrus.Entry) ([]byte, error) {
	data := make(logrus.Fields, len(entry.Data)+3)
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			// Otherwise errors are ignored by `encoding/json`
			// https://github.com/Sirupsen/logrus/issues/137
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	data["time"] = entry.Time.Format("15:04:05")
	data["msg"] = entry.Message

	// TODO: use sprintf
	str := "["
	if data["time"] != nil {
		str += data["time"].(string)
	}
	str += "] "
	if data["msg"] != nil {
		str += data["msg"].(string)
	}
	str += "\n"
	return []byte(str), nil
}

var logrusLogger *logrus.Logger
var initLoggerOnce sync.Once

func Logger() *logrus.Logger {
	initLoggerOnce.Do(func() {
		logrusLogger = logrus.New()
		logrusLogger.Formatter = new(formatter)
		logrusLogger.Level = logrus.InfoLevel
	})
	return logrusLogger
}
