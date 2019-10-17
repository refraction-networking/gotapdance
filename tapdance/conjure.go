package tapdance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

//[TODO]{priority:winter-break} make this not constant
const defaultRegWidth = 5

// DialConjureAddr - Perform Registration and Dial after creating  a Conjure session from scratch
func DialConjureAddr(ctx context.Context, address string) (net.Conn, error) {
	cjSession := makeConjureSession(address)
	return DialConjure(ctx, cjSession)
}

// DialConjure - Perform Registration and Dial on an existing Conjure session
func DialConjure(ctx context.Context, cjSession *ConjureSession) (net.Conn, error) {

	if cjSession == nil {
		return nil, fmt.Errorf("No Session Provided")
	}

	// Choose Phantom Address in Register depending on v6 support.
	err := Register(cjSession)
	if err != nil {
		Logger().Tracef("%v Failed to register: %v", cjSession.IDString(), err)
		return nil, err
	}

	Logger().Tracef("%v Successfully sent registrations", cjSession.IDString())
	// randomized sleeping here to break the intraflow signal
	cjSession.randomSleep()

	Logger().Tracef("%v Woke from sleep, attempting Connection...", cjSession.IDString())
	return Connect(cjSession)
}

// Register - Send registrations equal to the width specified in the Conjure Session
func Register(cjSession *ConjureSession) error {
	var err error

	// Choose N (width) decoys from decoylist
	if cjSession.useV4() {
		cjSession.RegDecoys = SelectDecoys(cjSession.Keys.SharedSecret, false, cjSession.Width)
		cjSession.Phantom, err = SelectPhantom(cjSession.Keys.ConjureSeed, false)
		if err != nil || cjSession.Phantom == nil {
			Logger().Warnf("%v failed to select Phantom: %v\n", cjSession.IDString(), err)
			return err
		}
		Logger().Tracef("%v Registering: %v (using v4)", cjSession.IDString(), cjSession.Phantom)

		return cjSession.register()
	}

	cjSession.RegDecoys = SelectDecoys(cjSession.Keys.SharedSecret, true, cjSession.Width)
	cjSession.Phantom, err = SelectPhantom(cjSession.Keys.ConjureSeed, true)
	if err != nil || cjSession.Phantom == nil {
		Logger().Warnf("%v failed to select Phantom: %v\n", cjSession.IDString(), err)
		return err
	}

	Logger().Tracef("%v Registering: %v (trying v6)", cjSession.IDString(), cjSession.Phantom)

	err = cjSession.register()

	// If we failed because all v6 decoys were unreachable
	if regErr, ok := err.(*RegError); ok && regErr.code == Unreachable {

		cjSession.V6Support.support = false
		cjSession.V6Support.checked = time.Now()

		// -> update settings and retry v4 only
		cjSession.RegDecoys = SelectDecoys(cjSession.Keys.SharedSecret, false, cjSession.Width)
		cjSession.Phantom, err = SelectPhantom(cjSession.Keys.ConjureSeed, false)
		if err != nil || cjSession.Phantom == nil {
			Logger().Warnf("%v failed to select Phantom: %v\n", cjSession.IDString(), err)
			return err
		}

		Logger().Tracef("%v Registering: %v (v6 failed using v4)", cjSession.IDString(), cjSession.Phantom)

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
	CovertAddress  string
	// rtt			   uint // tracked in stats

	// Is this the correct place for this (maybe in dialer stats somehow??)
	failedDecoys []string

	// performance tracking
	stats *pb.SessionStats
}

// Define transports here=p0
//[TODO]{priority:winter-break} make this it's own type / interface
const (
	// MinTransport - Minimal transport used to connect  station (default)
	MinTransport uint = iota

	// Obfs4Transport - Use Obfs4 to provide probe resistant connection to station (not yet implemented)
	Obfs4Transport
)

func makeConjureSession(covert string) *ConjureSession {

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
		CovertAddress:  covert,
		SessionID:      sessionsTotal.GetAndInc(),
	}

	dst := make([]byte, hex.EncodedLen(len(keys.SharedSecret)))
	hex.Encode(dst, keys.SharedSecret)
	Logger().Debugf("%v Shared Secret - %s", cjSession.IDString(), dst)

	return cjSession
}

// IDString - Get the ID string for the session
func (cjSession *ConjureSession) IDString() string {
	if cjSession.Keys == nil || cjSession.Keys.SharedSecret == nil {
		return fmt.Sprintf("[%v-000000]", strconv.FormatUint(cjSession.SessionID, 10))
	}

	secret := make([]byte, hex.EncodedLen(len(cjSession.Keys.SharedSecret)))
	n := hex.Encode(secret, cjSession.Keys.SharedSecret)
	if n < 6 {
		return fmt.Sprintf("[%v-000000]", strconv.FormatUint(cjSession.SessionID, 10))
	}
	return fmt.Sprintf("[%v-%s]", strconv.FormatUint(cjSession.SessionID, 10), secret[:6])
}

// String - Print the string for debug and/or logging
func (cjSession *ConjureSession) String() string {
	return cjSession.IDString()
	// expand for debug??
}

func (cjSession *ConjureSession) register() error {
	//[reference] Prepare registration
	reg := &ConjureReg{
		sessionIDStr:  cjSession.IDString(),
		keys:          cjSession.Keys,
		stats:         &pb.SessionStats{},
		phantom:       cjSession.Phantom,
		v6Support:     cjSession.V6Support.support,
		covertAddress: cjSession.CovertAddress,
	}

	// //[TODO]{priority:later} How to pass context to multiple registration goroutines?
	// ctx := context.Background()

	width := uint(len(cjSession.RegDecoys))
	if width < cjSession.Width {
		Logger().Warnf("%v Using width %v (default %v)", cjSession.IDString(), width, cjSession.Width)
	}

	Logger().Debugf("%v Registration - v6:%v, covert:%v, phantom:%v", reg.sessionIDStr, reg.v6Support, reg.covertAddress, reg.phantom)

	//[reference] Send registrations to each decoy
	dialErrors := make(chan error, width)
	for _, decoy := range cjSession.RegDecoys {
		Logger().Debugf("%v Sending Reg: %v (%v)", cjSession.IDString(), decoy.GetHostname(), decoy.GetIpAddrStr())
		//decoyAddr := decoy.GetIpAddrStr()
		go reg.send(decoy, dialErrors, cjSession.registrationCallback)
	}

	//[reference] Dial errors happen immediately so block until all N dials complete
	var unreachableCount uint = 0
	for err := range dialErrors {
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "connect: network is unreachable" {
				// If we failed because ipv6 network was unreachable try v4 only.
				unreachableCount++
				continue
			}
		}
		// if we succeed or fail for any other reason network is reachable and we can continue
		break
	}

	Logger().Tracef("We make it past dialErrs in the parent")

	//[reference] if ALL fail to dial return error (retry in parent if ipv6 unreachable)
	if unreachableCount == width {
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
		//[TODO]{priority:@sfrolov} explain these numbers and why they were chosen for the boundaries.
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
		//[TODO]{priority:winter-break} add Obfs4 Transport
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
	phantom        *net.IP
	useProxyHeader bool
	covertAddress  string
	phantomSNI     string
	v6Support      bool

	stats *pb.SessionStats

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
func (reg *ConjureReg) send(decoy *pb.TLSDecoySpec, dialError chan error, callback func(*ConjureReg, error)) {

	ctx := context.Background()

	//[reference] TCP to decoy
	tcpToDecoyStartTs := time.Now()

	//[Note] decoy.GetIpAddrStr() will get only v4 addr if a decoy has both
	dialConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", decoy.GetIpAddrStr())
	reg.setTCPToDecoy(durationToU32ptrMs(time.Since(tcpToDecoyStartTs)))
	if err != nil {
		dialError <- err
		return
	}

	//[reference] connection stats tracking
	rtt := rttInt(*reg.stats.TcpToDecoy)
	delay := getRandomDuration(1061*rtt*2, 1953*rtt*3) //[TODO]{priority:@sfrolov} why these values??
	deadline := time.Now().Add(delay)

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
	//[TODO]{priority:winter-break} parroting Chrome 62 ClientHello -- parrot newer.
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

	tlsConn.SetDeadline(deadline)
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
	callback(reg, err)
}

func (reg *ConjureReg) setTCPToDecoy(tcprtt *uint32) {
	//[TODO]{priority:now} Mutex lock this or you will be unhappy
	if reg.stats == nil {
		reg.stats = &pb.SessionStats{}
	}
	reg.stats.TcpToDecoy = tcprtt
}

func (reg *ConjureReg) setTLSToDecoy(tlsrtt *uint32) {
	//[TODO]{priority:now} Mutex lock this or you will be unhappy
	if reg.stats == nil {
		reg.stats = &pb.SessionStats{}
	}
	reg.stats.TlsToDecoy = tlsrtt
}

func (reg *ConjureReg) generateVSP() ([]byte, error) {
	var covert *string
	if len(reg.covertAddress) > 0 {
		//[TODO]{priority:winter-break} this isn't the correct place to deal with signaling to the station
		//transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &reg.covertAddress
	}

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	currentGen := Assets().GetGeneration()
	initProto := &pb.ClientToStation{
		CovertAddress:       covert,
		DecoyListGeneration: &currentGen,
		V6Support:           &reg.v6Support,
		// StateTransition:     &transition,

		//[TODO]{priority:winter-break} specify width in C2S because different width might
		// 		be useful in different regions (constant for now.)
	}

	if len(reg.phantomSNI) > 0 {
		initProto.MaskedDecoyServerName = &reg.phantomSNI
	}

	initProto.V6Support = &reg.v6Support

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

	if reg.useProxyHeader {
		flags |= tdFlagProxyHeader
	}
	buf[2] = flags

	return buf
}

func (reg *ConjureReg) digestStats() string {
	//[TODO]{priority:eventually} add decoy details to digest
	if reg == nil || reg.stats == nil {
		return fmt.Sprint("{result:\"no stats tracked\"}")
	}
	return fmt.Sprintf("{result:\"success\", tcp_to_decoy:%v, tls_to_decoy:%v, total_time_to_connect:%v}",
		reg.stats.GetTcpToDecoy(),
		reg.stats.GetTlsToDecoy(),
		reg.stats.GetTotalTimeToConnect())
}

// When a registration send goroutine finishes it will call this and log
//	 	session stats and/or errors.
func (cjSession *ConjureSession) registrationCallback(reg *ConjureReg, err error) {
	//[TODO]{priority:NOW}
	Logger().Infof("%v %v - %v", cjSession.IDString(), reg.digestStats(), err)
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
	rtt := rttInt(cjSession.getTcpToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}

func (cjSession *ConjureSession) getTcpToDecoy() uint32 {
	if cjSession != nil {
		if cjSession.stats != nil {
			return cjSession.stats.GetTcpToDecoy()
		}
	}
	return 0
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
func SelectDecoys(sharedSecret []byte, useV6 bool, width uint) []*pb.TLSDecoySpec {

	//[reference] prune to v6 only decoys if useV6 is true
	var allDecoys []*pb.TLSDecoySpec
	if useV6 {
		allDecoys = Assets().GetV6Decoys()
	} else {
		allDecoys = Assets().GetAllDecoys()
	}

	decoys := make([]*pb.TLSDecoySpec, width)
	numDecoys := big.NewInt(int64(len(allDecoys)))
	hmacInt := new(big.Int)
	idx := new(big.Int)

	//[referece] select decoys
	for i := uint(0); i < width; i++ {
		macString := fmt.Sprintf("registrationdecoy%d", i)
		hmac := conjureHMAC(sharedSecret, macString)
		hmacInt = hmacInt.SetBytes(hmac[:8])
		hmacInt.SetBytes(hmac)
		hmacInt.Abs(hmacInt)
		idx.Mod(hmacInt, numDecoys)
		decoys[i] = allDecoys[int(idx.Int64())]
	}
	return decoys
}

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(seed []byte, v6Support bool) (*net.IP, error) {
	// Full \32 is routed in v6
	// Full \8 is routed in v4 (some is unused) and live on limited basis (belinging to michigan) 35.0.0.0\8
	ddIPSelector, err := newDDIpSelector([]string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}, v6Support)
	if err != nil {
		return nil, err
	}

	darkDecoyIPAddr, err := ddIPSelector.selectIpAddr(seed)
	if err != nil {
		return nil, err
	}
	return darkDecoyIPAddr, nil
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
