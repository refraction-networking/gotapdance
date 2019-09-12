package tapdance

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func aesGcmEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGcmCipher.Seal(nil, iv, plaintext, nil), nil
}

// Tries to get crypto random int in range [min, max]
// In case of crypto failure -- return insecure pseudorandom
func getRandInt(min int, max int) int {
	// I can't believe Golang is making me do that
	// Flashback to awful C/C++ libraries
	diff := max - min
	if diff < 0 {
		Logger().Warningf("getRandInt(): max is less than min")
		min = max
		diff *= -1
	} else if diff == 0 {
		return min
	}
	var v int64
	err := binary.Read(rand.Reader, binary.LittleEndian, &v)
	if v < 0 {
		v *= -1
	}
	if err != nil {
		Logger().Warningf("Unable to securely get getRandInt(): " + err.Error())
		v = mrand.Int63()
	}
	return min + int(v%int64(diff+1))
}

// returns random duration between min and max in milliseconds
func getRandomDuration(min int, max int) time.Duration {
	return time.Millisecond * time.Duration(getRandInt(min, max))
}

// Get padding of length [minLen, maxLen).
// Distributed in pseudogaussian style.
// Padded using symbol '#'. Known plaintext attacks, anyone?
func getRandPadding(minLen int, maxLen int, smoothness int) string {
	paddingLen := 0
	for j := 0; j < smoothness; j++ {
		paddingLen += getRandInt(minLen, maxLen)
	}
	paddingLen = paddingLen / smoothness

	return strings.Repeat("#", paddingLen)
}

func getRandString(length int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randString := make([]byte, length)
	for i := range randString {
		randString[i] = alphabet[getRandInt(0, len(alphabet)-1)]
	}
	return string(randString)
}

type tapdanceSharedKeys struct {
	FspKey, FspIv, VspKey, VspIv, NewMasterSecret, DarkDecoySeed []byte
}

func genSharedKeys(sharedSecret []byte) (tapdanceSharedKeys, error) {
	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("tapdancetapdancetapdancetapdance"), nil)
	keys := tapdanceSharedKeys{
		FspKey:          make([]byte, 16),
		FspIv:           make([]byte, 12),
		VspKey:          make([]byte, 16),
		VspIv:           make([]byte, 12),
		NewMasterSecret: make([]byte, 48),
		DarkDecoySeed:   make([]byte, 16),
	}

	if _, err := tdHkdf.Read(keys.FspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.FspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.NewMasterSecret); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.DarkDecoySeed); err != nil {
		return keys, err
	}
	return keys, nil
}

func getMsgWithHeader(msgType msgType, msgBytes []byte) []byte {
	if len(msgBytes) == 0 {
		return nil
	}
	bufSend := new(bytes.Buffer)
	var err error
	switch msgType {
	case msgProtobuf:
		if len(msgBytes) <= int(maxInt16) {
			bufSend.Grow(2 + len(msgBytes)) // to avoid double allocation
			err = binary.Write(bufSend, binary.BigEndian, int16(len(msgBytes)))

		} else {
			bufSend.Grow(2 + 4 + len(msgBytes)) // to avoid double allocation
			bufSend.Write([]byte{0, 0})
			err = binary.Write(bufSend, binary.BigEndian, int32(len(msgBytes)))
		}
	case msgRawData:
		err = binary.Write(bufSend, binary.BigEndian, int16(-len(msgBytes)))
	default:
		panic("getMsgWithHeader() called with msgType: " + strconv.Itoa(int(msgType)))
	}
	if err != nil {
		// shouldn't ever happen
		Logger().Errorln("getMsgWithHeader() failed with error: ", err)
		Logger().Errorln("msgType ", msgType)
		Logger().Errorln("msgBytes ", msgBytes)
	}
	bufSend.Write(msgBytes)
	return bufSend.Bytes()
}

func uint16toInt16(i uint16) int16 {
	pos := int16(i & 32767)
	neg := int16(0)
	if i&32768 != 0 {
		neg = int16(-32768)
	}
	return pos + neg
}

// generates HTTP request, that is ready to have tag prepended to it
func generateHTTPRequestBeginning(decoyHostname string) []byte {
	sharedHeaders := `Host: ` + decoyHostname +
		"\nUser-Agent: TapDance/1.2 (+https://refraction.network/info)"
	httpTag := fmt.Sprintf(`GET / HTTP/1.1
%s
X-Ignore: %s`, sharedHeaders, getRandPadding(7, maxInt(612-len(sharedHeaders), 7), 10))
	return []byte(strings.Replace(httpTag, "\n", "\r\n", -1))
}

func reverseEncrypt(ciphertext []byte, keyStream []byte) []byte {
	var plaintext string
	// our plaintext can be antyhing where x & 0xc0 == 0x40
	// i.e. 64-127 in ascii (@, A-Z, [\]^_`, a-z, {|}~ DEL)
	// This means that we are allowed to choose the last 6 bits
	// of each byte in the ciphertext arbitrarily; the upper 2
	// bits will have to be 01, so that our plaintext ends up
	// in the desired range.
	var ka, kb, kc, kd byte // key stream bytes
	var ca, cb, cc, cd byte // ciphertext bytes
	var pa, pb, pc, pd byte // plaintext bytes
	var sa, sb, sc byte     // secret bytes

	var tagIdx, keystreamIdx int

	for tagIdx < len(ciphertext) {
		ka = keyStream[keystreamIdx]
		kb = keyStream[keystreamIdx+1]
		kc = keyStream[keystreamIdx+2]
		kd = keyStream[keystreamIdx+3]
		keystreamIdx += 4

		// read 3 bytes
		sa = ciphertext[tagIdx]
		sb = ciphertext[tagIdx+1]
		sc = ciphertext[tagIdx+2]
		tagIdx += 3

		// figure out what plaintext needs to be in base64 encode
		ca = (ka & 0xc0) | ((sa & 0xfc) >> 2)                        // 6 bits sa
		cb = (kb & 0xc0) | (((sa & 0x03) << 4) | ((sb & 0xf0) >> 4)) // 2 bits sa, 4 bits sb
		cc = (kc & 0xc0) | (((sb & 0x0f) << 2) | ((sc & 0xc0) >> 6)) // 4 bits sb, 2 bits sc
		cd = (kd & 0xc0) | (sc & 0x3f)                               // 6 bits sc

		// Xor with key_stream, and add on 0x40 so it's in range of allowed
		pa = (ca ^ ka) + 0x40
		pb = (cb ^ kb) + 0x40
		pc = (cc ^ kc) + 0x40
		pd = (cd ^ kd) + 0x40

		plaintext += string(pa)
		plaintext += string(pb)
		plaintext += string(pc)
		plaintext += string(pd)
	}
	return []byte(plaintext)
}

func minInt(a, b int) int {
	if a > b {
		return b
	}
	return a
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Converts provided duration to raw milliseconds.
// Returns a pointer to u32, because protobuf wants pointers.
// Max valid input duration (that fits into uint32): 49.71 days.
func durationToU32ptrMs(d time.Duration) *uint32 {
	i := uint32(d.Nanoseconds() / int64(time.Millisecond))
	return &i
}

func readAndClose(c net.Conn, readDeadline time.Duration) {
	tinyBuf := []byte{0}
	c.SetReadDeadline(time.Now().Add(readDeadline))
	c.Read(tinyBuf)
	c.Close()
}

func errIsTimeout(err error) bool {
	if err != nil {
		if strings.Contains(err.Error(), ": i/o timeout") || // client timed out
			err.Error() == "EOF" { // decoy timed out
			return true
		}
	}
	return false
}

type ddIpSelector struct {
	nets []net.IPNet
}

func newDDIpSelector(netsStr []string, v6Support bool) (*ddIpSelector, error) {
	dd := ddIpSelector{}
	for _, _netStr := range netsStr {
		_, _net, err := net.ParseCIDR(_netStr)
		if err != nil {
			return nil, err
		}
		if _net == nil {
			return nil, fmt.Errorf("failed to parse %v as subnet", _netStr)
		}

		// Split out IPv4 and IPv6 for clients that do not support IPv6
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			dd.nets = append(dd.nets, *_net)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			if v6Support {
				dd.nets = append(dd.nets, *_net)
			}
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}
	return &dd, nil
}

func (d *ddIpSelector) selectIpAddr(seed []byte) (*net.IP, error) {
	addresses_total := big.NewInt(0)

	type idNet struct {
		min, max big.Int
		net      net.IPNet
	}
	var idNets []idNet

	for _, _net := range d.nets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addresses_total)
			addresses_total.Add(addresses_total, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			addresses_total.Sub(addresses_total, big.NewInt(1))
			_idNet.max.Set(addresses_total)
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addresses_total)
			addresses_total.Add(addresses_total, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
			addresses_total.Sub(addresses_total, big.NewInt(1))
			_idNet.max.Set(addresses_total)
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}
	id := &big.Int{}
	id.SetBytes(seed)
	if id.Cmp(addresses_total) >= 0 {
		id.Mod(id, addresses_total)
	}

	var result net.IP
	for _, _idNet := range idNets {
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) == -1 {
			if ipv4net := _idNet.net.IP.To4(); ipv4net != nil {
				ipBigInt := &big.Int{}
				ipBigInt.SetBytes(ipv4net)
				ipNetDiff := _idNet.max.Sub(id, &_idNet.min)
				ipBigInt.Add(ipBigInt, ipNetDiff)
				result = net.IP(ipBigInt.Bytes()).To4() // implicit check that it fits
			} else if ipv6net := _idNet.net.IP.To16(); ipv6net != nil {
				ipBigInt := &big.Int{}
				ipBigInt.SetBytes(ipv6net)
				ipNetDiff := _idNet.max.Sub(id, &_idNet.min)
				ipBigInt.Add(ipBigInt, ipNetDiff)
				result = net.IP(ipBigInt.Bytes()).To16()
			} else {
				return nil, fmt.Errorf("failed to parse %v", _idNet.net.IP)
			}
		}
	}
	if result == nil {
		return nil, errors.New("let's rewrite dark decoy selector")
	}
	return &result, nil
}
