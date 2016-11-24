package tapdance

import "github.com/Sirupsen/logrus"

type MyFormatter struct {
}

func (f *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
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
