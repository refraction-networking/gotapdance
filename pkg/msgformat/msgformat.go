package msgformat

import (
	"errors"
	"log"
)

// Prefix length to message
func AddFormat(p []byte) ([]byte, error) {
	length := uint8(len(p))
	log.Println("AddFormat(): len=", length)
	prefixed := append([]byte{length}, p...)
	return prefixed, nil
}

// Read the first byte as length of message and return the message accordingly
func RemoveFormat(p []byte) ([]byte, error) {
	length := uint8(p[0])
	if int(1+length) > len(p) {
		return nil, errors.New("invalid message length recieved")
	}
	return p[1 : 1+length], nil
}
