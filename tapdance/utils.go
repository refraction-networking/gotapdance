package tapdance

import (
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"encoding/binary"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/rand"
	"crypto/aes"

	"fmt"

	"time"
	"bytes"
)

func AesGcmEncrypt(plaintext []byte, key []byte, iv []byte) (ciphertext []byte, err error) {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	aesGcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	ciphertext = aesGcmCipher.Seal(nil, iv, plaintext, nil)
	return
}

func AesGcmDecrypt(ciphertext []byte, key []byte, iv []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	aesGcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	plaintext, err = aesGcmCipher.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return
	}
	return
}


func obfuscateTag(stegoPayload []byte, stationPubkey [32]byte) (tag []byte, err error) {
	var sharedSecret, clientPrivate, clientPublic, representative [32]byte
	for ok := false; ok != true; {
		var slice_key_private []byte = clientPrivate[:]
		rand.Read(slice_key_private)

		clientPrivate[0] &= 248
		clientPrivate[31] &= 127
		clientPrivate[31] |= 64

		ok = extra25519.ScalarBaseMult(&clientPublic, &representative, &clientPrivate)
	}

	curve25519.ScalarMult(&sharedSecret, &clientPrivate, &stationPubkey)

	tagBuf := new(bytes.Buffer) // What we have to encrypt with the shared secret using AES
	tagBuf.Write(representative[:])

	stationPubkeyHash := sha256.Sum256(sharedSecret[:])
	aesKey := stationPubkeyHash[:16]
	aesIv := stationPubkeyHash[16:28]

	data := make([]byte, 2 + len(stegoPayload))
	binary.BigEndian.PutUint16(data, uint16(len(stegoPayload)))
	copy(data[2:], stegoPayload)

	encryptedData, err := AesGcmEncrypt(data, aesKey, aesIv)
	if err != nil {
		return
	}

	tagBuf.Write(encryptedData)
	tag = tagBuf.Bytes()
	Logger.Debugf("len(tag)", tagBuf.Len())
	return
}

func timeMs() int64 {
	return time.Now().UnixNano() / (int64(time.Millisecond)/int64(time.Nanosecond))
}

func printHex(byteArray []byte, name string) {
	fmt.Print(name, ": [")
	for i := 0; i < len(byteArray); i++ {
		if byteArray[i] >= 0x10 {
			//fmt.Printf("%x", byte_array[i])
			fmt.Printf("%v, ", byteArray[i])
		} else {
		//	fmt.Printf("0%x", byte_array[i])
			fmt.Printf("%v, ", byteArray[i])
		}
	}
	fmt.Println("]")
}