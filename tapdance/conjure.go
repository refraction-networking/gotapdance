package tapdance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// V6 - Struct to track V6 support and cache result across sessions
type V6 struct {
	support bool
	checked time.Time
}

//[TODO] remove this it is unused.
const (
	v4 = iota
	v6
	both
)

const defaultRegWidth = 5

// DialConjure - Perform Registration and Dial to create a Conjure session
func DialConjure(ctx context.Context, cjSession *ConjureSession) (net.Conn, error) {

	if cjSession == nil {
		cjSession = makeConjureSession()
	}
	cjSession.SessionID = sessionsTotal.GetAndInc()

	// Choose Phantom Address in Register depending on v6 support.
	err := Register(cjSession)
	if err != nil {
		return nil, err
	}

	// randomized sleeping here to break the intraflow signal
	cjSession.randomSleep()

	return Connect(cjSession)
}

// Register - Send registrations equal to the width specified in the Conjure Session
func Register(cjSession *ConjureSession) error {
	var err error

	// Choose N (width) decoys from decoylist
	if cjSession.useV4() {
		cjSession.RegDecoys = SelectDecoys(cjSession.Keys, false, cjSession.Width)
		cjSession.Phantom, err = SelectPhantom(cjSession.Keys, false)
		if err != nil {
			return err
		}

		return cjSession.register()
	}

	cjSession.RegDecoys = SelectDecoys(cjSession.Keys, true, cjSession.Width)
	cjSession.Phantom, err = SelectPhantom(cjSession.Keys, true)
	if err != nil {
		return err
	}
	err = cjSession.register()

	// If we failed because all v6 decoys were unreachable
	if regErr, ok := err.(*RegError); ok && regErr.code == Unreachable {
		cjSession.V6Support.support = false
		cjSession.V6Support.checked = time.Now()

		// -> update settings and retry v4 only
		cjSession.RegDecoys = SelectDecoys(cjSession.Keys, false, cjSession.Width)
		cjSession.Phantom, err = SelectPhantom(cjSession.Keys, false)
		if err != nil {
			return err
		}

		err = cjSession.register()
	}
	return err
}

// Connect - Dial the Phantom IP address after registration
func Connect(cjSession *ConjureSession) (net.Conn, error) {
	return cjSession.connect(context.Background())
}

// ConjureSession - Create a session with details for registration and connection
type ConjureSession struct {
	Keys           *sharedKeys
	Width          uint
	V6Support      V6
	UseProxyHeader bool
	SessionID      uint64
	RegDecoys      []*pb.TLSDecoySpec // pb.DecoyList
	Phantom        *net.IP
	Transport      uint
	// rtt			   uint // tracked in stats

	// Is this the correct place for this (maybe in dialer stats somehow??)
	failedDecoys []string

	// performance tracking
	stats pb.SessionStats
}

// Define transports here
//[TODO] make this it's own type / interface
const (
	// MinTransport - Minimal transport used to connect  station (default)
	MinTransport uint = iota

	// Obfs4Transport - Use Obfs4 to provide probe resistant connection to station (not yet implemented)
	Obfs4Transport
)

func makeConjureSession() *ConjureSession {

	keys, err := generateSharedKeys(getStationKey())
	if err != nil {
		return nil
	}

	cjSession := &ConjureSession{
		Keys:           keys,
		Width:          defaultRegWidth,
		V6Support:      V6{true, time.Now()},
		UseProxyHeader: false,
		Transport:      MinTransport,
	}

	return cjSession
}

// IDString - Get the ID string for the session
func (cjSession *ConjureSession) IDString() string {
	return fmt.Sprintf("[Session %v]", strconv.FormatUint(cjSession.SessionID, 10))
}

// String - Print the string for debug and/or logging
func (cjSession *ConjureSession) String() string {
	return fmt.Sprintf("[Session %v]", strconv.FormatUint(cjSession.SessionID, 10))
	// expand??
}

func (cjSession *ConjureSession) register() error {
	// Prepare registration
	reg := &ConjureReg{sessionIDStr: cjSession.IDString(), keys: cjSession.Keys}

	ctx := context.Background()
	rtt := rttInt(*cjSession.stats.TcpToDecoy)
	delay := getRandomDuration(1061*rtt*2, 1953*rtt*3) // TODO: why these values??
	deadline := time.Now().Add(delay)
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	// send registrations to each decoy
	dialErrors := make(chan error, cjSession.Width)
	for _, decoy := range cjSession.RegDecoys {
		//decoyAddr := decoy.GetIpAddrStr()
		go reg.send(childCtx, decoy, dialErrors)
	}

	//	Dial errors happen immediately so block until all N dials complete
	var unreachableCount uint = 0
	for err := range dialErrors {
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "connect: network is unreachable" {
				// If we failed because ipv6 network was unreachable try v4 only.
				unreachableCount++
			}
		}
	}

	// if ALL fail to dial return error (retry in parent if ipv6 unreachable)
	if unreachableCount == cjSession.Width {
		return &RegError{code: Unreachable, msg: "All decoys failed to register -- Dial Unreachable"}
	}

	return nil
}

func (cjSession *ConjureSession) connect(ctx context.Context) (net.Conn, error) {
	//[reference] Create Context with deadline
	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		//[reference] randomized timeout to Dial dark decoy address
		deadline = time.Now().Add(cjSession.getRandomDuration(0, 1061*2, 1953*3))
		//[TODO] @sfrolov explain these numbers and why they were chosen for the boundaries.
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] Connect to Phantom Host using TLS
	phantomAddr := net.JoinHostPort(cjSession.Phantom.String(), "443")

	conn, err := (&net.Dialer{}).DialContext(childCtx, "tcp", phantomAddr)
	if err != nil {
		Logger().Infof("%v failed to dial phantom %v: %v\n", cjSession.IDString(), cjSession.Phantom.String(), err)
		return nil, err
	}
	Logger().Infof("%v Connected to phantom %v", cjSession.IDString(), phantomAddr)

	//[reference] Provide chosen transport to sent bytes (or connect) if necessary
	switch cjSession.Transport {
	case MinTransport:
		// Send hmac(seed, str) bytes to indicate to station (min transport)
		connectTag := conjureHMAC(cjSession.Keys.SharedSecret, "MinTrasportHMACString")
		conn.Write(connectTag)
	case Obfs4Transport:
		//[TODO] add Obfs4 Transport
		return nil, fmt.Errorf("connect not yet implemented")

	default:
		// If transport is unrecognized use min transport.
		connectTag := conjureHMAC(cjSession.Keys.SharedSecret, "MinTrasportHMACString")
		conn.Write(connectTag)
	}

	return nil, nil
}

// ConjureReg - Registration structure created for each individual registration within a session.
type ConjureReg struct {
	seed           []byte
	sessionIDStr   string
	phantom        net.IP
	useProxyHeader bool
	covertAddress  string
	phantomSNI     string
	v6Support      bool

	keys *sharedKeys
}

func (reg *ConjureReg) createRequest(tlsConn *tls.UConn, decoy *pb.TLSDecoySpec) ([]byte, error) {
	//[reference] generate and encrypt variable size payload
	vsp, err := reg.generateVSP()
	if err != nil {
		return nil, err
	}
	if len(vsp) > int(^uint16(0)) {
		return nil, fmt.Errorf("Variable-Size Payload exceeds %v", ^uint16(0))
	}
	encryptedVsp, err := aesGcmEncrypt(vsp, reg.keys.VspKey, reg.keys.VspIv)
	if err != nil {
		return nil, err
	}

	//[reference] generate and encrypt fixed size payload
	fsp := reg.generateFSP(uint16(len(encryptedVsp)))
	encryptedFsp, err := aesGcmEncrypt(fsp, reg.keys.FspKey, reg.keys.FspIv)
	if err != nil {
		return nil, err
	}

	var tag []byte // tag will be base-64 style encoded
	tag = append(encryptedVsp, reg.keys.Representative...)
	tag = append(tag, encryptedFsp...)

	httpRequest := generateHTTPRequestBeginning(decoy.GetHostname())
	keystreamOffset := len(httpRequest)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	wholeKeystream, err := tlsConn.GetOutKeystream(keystreamSize)
	if err != nil {
		return nil, err
	}
	keystreamAtTag := wholeKeystream[keystreamOffset:]
	httpRequest = append(httpRequest, reverseEncrypt(tag, keystreamAtTag)...)
	httpRequest = append(httpRequest, []byte("\r\n\r\n")...)
	return httpRequest, nil
}

// Being called in parallel -> no changes to ConjureReg allowed in this function
func (reg *ConjureReg) send(ctx context.Context, decoy *pb.TLSDecoySpec, dialError chan error) {

	//[reference] TCP to decoy
	//tcpToDecoyStartTs := time.Now()
	dialConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", decoy.GetIpAddrStr())
	// tcpToDecoyTotalTs := time.Since(tcpToDecoyStartTs)
	if err != nil {
		dialError <- err
		dialConn.Close()
		return
	}

	//[reference] TLS to Decoy
	config := tls.Config{ServerName: decoy.GetHostname()}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(decoy.GetIpAddrStr())
		if err != nil {
			dialConn.Close()
			dialError <- err
			return
		}
		Logger().Infoln(reg.sessionIDStr + ": SNI was nil. Setting it to" +
			config.ServerName)
	}
	//[TODO] parroting Chrome 62 ClientHello -- parrot newer.
	tlsConn := tls.UClient(dialConn, &config, tls.HelloChrome_62)
	err = tlsConn.BuildHandshakeState()
	if err != nil {
		dialConn.Close()
		dialError <- err
		return
	}
	err = tlsConn.MarshalClientHello()
	if err != nil {
		dialConn.Close()
		dialError <- err
		return
	}
	//[TODO] add deadline timeout to tls connection to registration decoys.
	// tlsConn.SetDeadline(deadline)
	err = tlsConn.Handshake()
	if err != nil {
		dialConn.Close()
		dialError <- err
		return
	}

	//[reference] Create the HTTP request for the registration
	httpRequest, err := reg.createRequest(tlsConn, decoy)
	if err != nil {
		dialError <- err
		return
	}

	//[reference] Write reg into conn
	_, err = tlsConn.Write(httpRequest)
	if err != nil {
		Logger().Errorf(reg.sessionIDStr +
			"Could not send initial TD request, error: " + err.Error())
		tlsConn.Close()
		return
	}

	readAndClose(dialConn, time.Second*15)
}

func (reg *ConjureReg) generateVSP() ([]byte, error) {
	var covert *string
	if len(reg.covertAddress) > 0 {
		//[TODO] this isn't the correct place to deal with signaling to the station
		//transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &reg.covertAddress
	}

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	currentGen := Assets().GetGeneration()
	initProto := &pb.ClientToStation{
		CovertAddress: covert,
		// StateTransition:     &transition,
		DecoyListGeneration: &currentGen,
	}

	if len(reg.phantomSNI) > 0 {
		initProto.MaskedDecoyServerName = &reg.phantomSNI
	}

	initProto.V6Support = &reg.v6Support
	Logger().Debugln(reg.sessionIDStr+" Initial protobuf", initProto)

	for (proto.Size(initProto)+AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}

	//[reference] Marshal ClientToStation protobuf
	return proto.Marshal(initProto)
}

func (reg *ConjureReg) generateFSP(espSize uint16) []byte {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], espSize)
	flags := default_flags

	//[TODO] share flags somehow
	if reg.useProxyHeader {
		flags |= tdFlagProxyHeader
	}
	buf[2] = flags

	return buf
}

func (cjSession *ConjureSession) useV4() bool {
	if cjSession.V6Support.support == true {
		return false
	} else if cjSession.V6Support.checked.Before(time.Now().Add(-2 * time.Hour)) {
		return false
	} else {
		return true
	}
}

func (cjSession *ConjureSession) getRandomDuration(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(*cjSession.stats.TcpToDecoy)
	return time.Millisecond * time.Duration(base+rtt*addon)
}

func (cjSession *ConjureSession) randomSleep() {
	toSleep := cjSession.getRandomDuration(300, 212, 3449)
	Logger().Debugf("%v Sleeping %v ms", cjSession.IDString(), toSleep)
	time.Sleep(toSleep)
}

func rttInt(millis uint32) int {
	defaultValue := 300
	if millis == 0 {
		return defaultValue
	}
	return int(millis)
}

// SelectDecoys - Get an array of `width` decoys to be used for registration
func SelectDecoys(keys *sharedKeys, v6Support bool, width uint) []*pb.TLSDecoySpec {
	//[TODO]: Prune for v6
	decoys := make([]*pb.TLSDecoySpec, width)
	allDecoys := Assets().GetAllDecoys()
	numDecoys := big.NewInt(int64(len(allDecoys)))

	var idx, macInt *big.Int

	for i := uint(0); i < width; i++ {
		macString := fmt.Sprintf("registrationdecoy%d", i)
		mac := conjureHMAC(keys.SharedSecret, macString)
		macInt = macInt.SetBytes(mac)
		macInt.SetBytes(mac)
		macInt.Abs(macInt)
		idx.Mod(macInt, numDecoys)
		decoys[i] = allDecoys[int(idx.Int64())]
	}
	return decoys
}

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(keys *sharedKeys, v6Support bool) (*net.IP, error) {
	//[TODO] Implement me
	return nil, &RegError{code: NotImplemented, msg: "SelectPhantom Not Implemented yet."}
}

func getStationKey() [32]byte {
	return *Assets().GetPubkey()
}

type sharedKeys struct {
	SharedSecret, Representative                               []byte
	FspKey, FspIv, VspKey, VspIv, NewMasterSecret, ConjureSeed []byte
}

func generateSharedKeys(pubkey [32]byte) (*sharedKeys, error) {
	sharedSecret, representative, err := generateEligatorTransformedKey(pubkey[:])
	if err != nil {
		return nil, err
	}

	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := &sharedKeys{
		SharedSecret:    sharedSecret,
		Representative:  representative,
		FspKey:          make([]byte, 16),
		FspIv:           make([]byte, 12),
		VspKey:          make([]byte, 16),
		VspIv:           make([]byte, 12),
		NewMasterSecret: make([]byte, 48),
		ConjureSeed:     make([]byte, 16),
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
	if _, err := tdHkdf.Read(keys.ConjureSeed); err != nil {
		return keys, err
	}
	return keys, nil
}

//
func conjureHMAC(key []byte, str string) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(str))
	return hash.Sum(nil)
}

// RegError - Registration Error passed during registration to indicate failure mode
type RegError struct {
	code uint
	msg  string
}

func (err *RegError) Error() string {
	return fmt.Sprintf("Registration Error [%v]: %v", err.code, err.msg)
}

const (
	// Unreachable -Dial Error Unreachable -- likely network unavailable (i.e. ipv6 error)
	Unreachable = iota

	// DialFailure - Dial Error Other than unreachable
	DialFailure

	// NotImplemented - Related Function Not Implemented
	NotImplemented

	// Unknown - Error occurred without obvious explanation
	Unknown
)

/*
func dialDarkDecoy(ctx context.Context, tdFlow *TapdanceFlowConn) (net.Conn, error) {

	// [reference] Session config
	tdFlow.tdRaw.tagType = tagHttpGetComplete
	tdFlow.flowType = flowRendezvous
	tdFlow.tdRaw.darkDecoyUsed = true

	// [reference] Register
	err = tdFlow.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	go readAndClose(tdFlow, time.Second*15)

	flowIdString := fmt.Sprintf("[Session %v]", strconv.FormatUint(tdFlow.tdRaw.sessionId, 10))
	darkDecoyIpAddr, err := _ddIpSelector.selectIpAddr(tdFlow.tdRaw.tdKeys.DarkDecoySeed)
	if err != nil {
		Logger().Infof("%v failed to select dark decoy: %v\n", tdFlow.idStr(), err)
		return nil, err
	}

	// [reference] Connect to phantom
	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		// randomized timeout to Dial dark decoy address
		deadline = time.Now().Add(getRandomDuration(1061*getRttMillisec()*2, 1953*getRttMillisec()*3))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	darkAddr := net.JoinHostPort(darkDecoyIpAddr.String(), "443")
	darkTcpConn, err := (&net.Dialer{}).DialContext(childCtx, "tcp", darkAddr)
	if err != nil {
		Logger().Infof("%v failed to dial dark decoy %v: %v\n",
			flowIdString, darkDecoyIpAddr.String(), err)
		return nil, err
	}
	Logger().Infof("%v Connected to dark decoy %v", flowIdString, darkAddr)

	return darkTcpConn, nil
}
*/
