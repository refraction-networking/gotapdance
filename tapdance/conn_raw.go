package tapdance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	tls "github.com/refraction-networking/utls"
	pb "github.com/sergeyfrolov/gotapdance/protobuf"
)

// Simply establishes TLS and TapDance connection.
// Both reader and writer flows shall have this underlying raw connection.
// Knows about but doesn't keep track of timeout and upload limit
type tdRawConn struct {
	tcpConn closeWriterConn // underlying TCP connection with CloseWrite() function that sends FIN
	tlsConn *tls.UConn      // TLS connection to decoy (and station)

	covert string // hostname that tapdance station will connect client to

	TcpDialer func(context.Context, string, string) (net.Conn, error)

	decoySpec     pb.TLSDecoySpec
	pinDecoySpec  bool // don't ever change decoy (still changeable from outside)
	initialMsg    pb.StationToClient
	stationPubkey []byte
	tagType       tdTagType

	remoteConnId []byte // 32 byte ID of the connection to station, used for reconnection

	establishedAt time.Time // right after TLS connection to decoy is established, but not to station
	UploadLimit   int       // used only in POST-based tags

	closed    chan struct{}
	closeOnce sync.Once

	// dark decoy variables
	darkDecoyUsed      bool
	darkDecoySNI       string
	darkDecoyV6Support bool

	// stats to report
	sessionStats pb.SessionStats
	failedDecoys []string

	// purely for logging and stats reporting purposes:
	flowId      uint64 // id of the flow within the session (=how many times reconnected)
	sessionId   uint64 // id of the local session
	strIdSuffix string // suffix for every log string (e.g. to mark upload-only flows)

	tdKeys tapdanceSharedKeys
}

func makeTdRaw(handshakeType tdTagType, stationPubkey []byte) *tdRawConn {
	tdRaw := &tdRawConn{tagType: handshakeType,
		stationPubkey: stationPubkey,
	}
	tdRaw.flowId = 0
	tdRaw.closed = make(chan struct{})
	return tdRaw
}

func (tdRaw *tdRawConn) DialContext(ctx context.Context) error {
	return tdRaw.dial(ctx, false)
}

func (tdRaw *tdRawConn) RedialContext(ctx context.Context) error {
	tdRaw.flowId += 1
	return tdRaw.dial(ctx, true)
}

func (tdRaw *tdRawConn) dial(ctx context.Context, reconnect bool) error {
	var maxConnectionAttempts int
	var err error

	dialStartTs := time.Now()
	var expectedTransition pb.S2C_Transition
	if reconnect {
		maxConnectionAttempts = 5
		expectedTransition = pb.S2C_Transition_S2C_CONFIRM_RECONNECT
		tdRaw.tlsConn.Close()
	} else {
		maxConnectionAttempts = 20
		expectedTransition = pb.S2C_Transition_S2C_SESSION_INIT
		if len(tdRaw.covert) > 0 {
			expectedTransition = pb.S2C_Transition_S2C_SESSION_COVERT_INIT
		}
	}

	for i := 0; i < maxConnectionAttempts; i++ {
		if tdRaw.IsClosed() {
			return errors.New("Closed")
		}
		// sleep to prevent overwhelming decoy servers
		if waitTime := sleepBeforeConnect(i); waitTime != nil {
			select {
			case <-waitTime:
			case <-ctx.Done():
				return context.Canceled
			case <-tdRaw.closed:
				return errors.New("Closed")
			}
		}
		if tdRaw.pinDecoySpec {
			if tdRaw.decoySpec.Ipv4Addr == nil {
				return errors.New("decoySpec is pinned, but empty!")
			}
		} else {
			if !reconnect {
				tdRaw.decoySpec = Assets().GetDecoy()
				if tdRaw.decoySpec.GetIpAddrStr() == "" {
					return errors.New("tdConn.decoyAddr is empty!")
				}
			}
		}

		if !reconnect {
			// generate a new remove conn ID for each attempt to dial
			// keep same remote conn ID for reconnect, since that's what it is for
			tdRaw.remoteConnId = make([]byte, 16)
			rand.Read(tdRaw.remoteConnId[:])
		}

		err = tdRaw.tryDialOnce(ctx, expectedTransition)
		if err == nil {
			tdRaw.sessionStats.TotalTimeToConnect = durationToU32ptrMs(time.Since(dialStartTs))
			return nil
		}
		tdRaw.failedDecoys = append(tdRaw.failedDecoys,
			tdRaw.decoySpec.GetHostname()+" "+tdRaw.decoySpec.GetIpAddrStr())
		if tdRaw.sessionStats.FailedDecoysAmount == nil {
			tdRaw.sessionStats.FailedDecoysAmount = new(uint32)
		}
		*tdRaw.sessionStats.FailedDecoysAmount += uint32(1)
	}
	return err
}

func (tdRaw *tdRawConn) tryDialOnce(ctx context.Context, expectedTransition pb.S2C_Transition) (err error) {
	Logger().Infoln(tdRaw.idStr() + " Attempting to connect to decoy " +
		tdRaw.decoySpec.GetHostname() + " (" + tdRaw.decoySpec.GetIpAddrStr() + ")")

	tlsToDecoyStartTs := time.Now()
	err = tdRaw.establishTLStoDecoy(ctx)
	tlsToDecoyTotalTs := time.Since(tlsToDecoyStartTs)
	if err != nil {
		Logger().Errorf(tdRaw.idStr() + " establishTLStoDecoy(" +
			tdRaw.decoySpec.GetHostname() + "," + tdRaw.decoySpec.GetIpAddrStr() +
			") failed with " + err.Error())
		return err
	}

	err = WriteTlsLog(tdRaw.tlsConn.HandshakeState.Hello.Random,
		tdRaw.tlsConn.HandshakeState.MasterSecret)
	if err != nil {
		Logger().Warningf("Failed to write TLS secret log: %s", err)
	}

	tdRaw.sessionStats.TlsToDecoy = durationToU32ptrMs(tlsToDecoyTotalTs)
	Logger().Infof("%s Connected to decoy %s(%s) in %s", tdRaw.idStr(), tdRaw.decoySpec.GetHostname(),
		tdRaw.decoySpec.GetIpAddrStr(), tlsToDecoyTotalTs.String())

	if tdRaw.IsClosed() {
		// if connection was closed externally while in establishTLStoDecoy()
		tdRaw.tlsConn.Close()
		return errors.New("Closed")
	}

	tdRequest, err := tdRaw.prepareTDRequest()
	if err != nil {
		Logger().Errorf(tdRaw.idStr() +
			" Preparation of initial TD request failed with " + err.Error())
		tdRaw.tlsConn.Close()
		return
	}
	tdRaw.establishedAt = time.Now() // TODO: recheck how ClientConf's timeout is calculated and move, if needed

	Logger().Infoln(tdRaw.idStr() + " Attempting to connect to TapDance Station" +
		" with connection ID: " + hex.EncodeToString(tdRaw.remoteConnId[:]) + ", method: " +
		tdRaw.tagType.Str())
	rttToStationStartTs := time.Now()
	_, err = tdRaw.tlsConn.Write(tdRequest)
	if err != nil {
		Logger().Errorf(tdRaw.idStr() +
			" Could not send initial TD request, error: " + err.Error())
		tdRaw.tlsConn.Close()
		return
	}

	// Give up waiting for the station pretty quickly (2x handshake time == ~4RTT)
	tdRaw.tlsConn.SetDeadline(time.Now().Add(tlsToDecoyTotalTs * 2))

	switch tdRaw.tagType {
	case tagHttpGetIncomplete:
		tdRaw.initialMsg, err = tdRaw.readProto()
		rttToStationTotalTs := time.Since(rttToStationStartTs)
		tdRaw.sessionStats.RttToStation = durationToU32ptrMs(rttToStationTotalTs)
		if err != nil {
			if errIsTimeout(err) {
				Logger().Errorf("%s %s: %v", tdRaw.idStr(),
					"TapDance station didn't pick up the request", err)

				// lame fix for issue #38 with abrupt drop of not picked up flows
				tdRaw.tlsConn.SetDeadline(time.Now().Add(
					getRandomDuration(deadlineTCPtoDecoyMin,
						deadlineTCPtoDecoyMax)))
				tdRaw.tlsConn.Write([]byte(getRandPadding(456, 789, 5) + "\r\n" +
					"Connection: close\r\n\r\n"))
				go readAndClose(tdRaw.tlsConn,
					getRandomDuration(deadlineTCPtoDecoyMin,
						deadlineTCPtoDecoyMax))
			} else {
				// any other error will be fatal
				Logger().Errorf(tdRaw.idStr() +
					" fatal error reading from TapDance station: " +
					err.Error())
				tdRaw.tlsConn.Close()
				return
			}
			return
		}
		if tdRaw.initialMsg.GetStateTransition() != expectedTransition {
			err = errors.New("Init error: state transition mismatch!" +
				" Received: " + tdRaw.initialMsg.GetStateTransition().String() +
				" Expected: " + expectedTransition.String())
			Logger().Infof("%s Failed to connect to TapDance Station [%s]: %s",
				tdRaw.idStr(), tdRaw.initialMsg.GetStationId(), err.Error())
			// this exceptional error implies that station has lost state, thus is fatal
			return err
		}
		Logger().Infoln(tdRaw.idStr() + " Successfully connected to TapDance Station [" + tdRaw.initialMsg.GetStationId() + "]")
	case tagHttpPostIncomplete, tagHttpGetComplete:
		// don't wait for response
	default:
		panic("Unsupported td handshake type:" + tdRaw.tagType.Str())
	}

	// TapDance should NOT have a timeout, timeouts have to be handled by client and server
	tdRaw.tlsConn.SetDeadline(time.Time{}) // unsets timeout
	return nil
}

func (tdRaw *tdRawConn) establishTLStoDecoy(ctx context.Context) error {
	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		deadline = time.Now().Add(getRandomDuration(deadlineTCPtoDecoyMin, deadlineTCPtoDecoyMax))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	tcpDialer := tdRaw.TcpDialer
	if tcpDialer == nil {
		// custom dialer is not set, use default
		d := net.Dialer{}
		tcpDialer = d.DialContext
	}

	tcpToDecoyStartTs := time.Now()
	dialConn, err := tcpDialer(childCtx, "tcp", tdRaw.decoySpec.GetIpAddrStr())
	tcpToDecoyTotalTs := time.Since(tcpToDecoyStartTs)
	if err != nil {
		return err
	}
	tdRaw.sessionStats.TcpToDecoy = durationToU32ptrMs(tcpToDecoyTotalTs)

	config := tls.Config{ServerName: tdRaw.decoySpec.GetHostname()}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(tdRaw.decoySpec.GetIpAddrStr())
		if err != nil {
			dialConn.Close()
			return err
		}
		Logger().Infoln(tdRaw.idStr() + ": SNI was nil. Setting it to" +
			config.ServerName)
	}
	// parrot Chrome 62 ClientHello
	tdRaw.tlsConn = tls.UClient(dialConn, &config, tls.HelloChrome_62)
	err = tdRaw.tlsConn.BuildHandshakeState()
	if err != nil {
		dialConn.Close()
		return err
	}
	err = tdRaw.tlsConn.MarshalClientHello()
	if err != nil {
		dialConn.Close()
		return err
	}
	tdRaw.tlsConn.SetDeadline(deadline)
	err = tdRaw.tlsConn.Handshake()
	if err != nil {
		dialConn.Close()
		return err
	}
	closeWriter, ok := dialConn.(closeWriterConn)
	if !ok {
		return errors.New("dialConn is not a closeWriter")
	}
	tdRaw.tcpConn = closeWriter
	return nil
}

func (tdRaw *tdRawConn) Close() error {
	var err error
	tdRaw.closeOnce.Do(func() {
		close(tdRaw.closed)
		if tdRaw.tlsConn != nil {
			err = tdRaw.tlsConn.Close()
		}
	})
	return err
}

type closeWriterConn interface {
	net.Conn
	CloseWrite() error
}

func (tdRaw *tdRawConn) closeWrite() error {
	return tdRaw.tcpConn.CloseWrite()
}

func (tdRaw *tdRawConn) generateVSP() ([]byte, error) {
	// Generate and marshal protobuf
	transition := pb.C2S_Transition_C2S_SESSION_INIT
	var covert *string
	if len(tdRaw.covert) > 0 {
		transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &tdRaw.covert
	}
	currGen := Assets().GetGeneration()
	initProto := &pb.ClientToStation{
		CovertAddress:       covert,
		StateTransition:     &transition,
		DecoyListGeneration: &currGen,
	}
	if tdRaw.darkDecoyUsed {
		initProto.MaskedDecoyServerName = &tdRaw.darkDecoySNI
		initProto.V6Support = &tdRaw.darkDecoyV6Support
	}
	Logger().Debugln(tdRaw.idStr()+" Initial protobuf", initProto)
	const AES_GCM_TAG_SIZE = 16
	for (proto.Size(initProto)+AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}
	return proto.Marshal(initProto)
}

func (tdRaw *tdRawConn) generateFSP(espSize uint16) []byte {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], espSize)

	flags := default_flags
	if tdRaw.tagType == tagHttpPostIncomplete {
		flags |= tdFlagUploadOnly
	}
	buf[2] = flags

	return buf
}

func (tdRaw *tdRawConn) prepareTDRequest() ([]byte, error) {

	sharedSecret, representative, err := generateEligatorTransformedKey(tdRaw.stationPubkey)
	if err != nil {
		return nil, err
	}

	tdKeys, err := genSharedKeys(sharedSecret)
	if err != nil {
		return nil, err
	}
	tdRaw.tdKeys = tdKeys

	// generate and encrypt variable size payload
	vsp, err := tdRaw.generateVSP()
	if err != nil {
		return nil, err
	}
	if len(vsp) > int(^uint16(0)) {
		return nil, fmt.Errorf("Variable-Size Payload exceeds %v", ^uint16(0))
	}
	encryptedVsp, err := aesGcmEncrypt(vsp, tdKeys.VspKey, tdKeys.VspIv)
	if err != nil {
		return nil, err
	}

	// generate and encrypt fixed size payload
	fsp := tdRaw.generateFSP(uint16(len(encryptedVsp)))
	encryptedFsp, err := aesGcmEncrypt(fsp, tdKeys.FspKey, tdKeys.FspIv)
	if err != nil {
		return nil, err
	}

	var tag []byte // tag will be base-64 style encoded
	tag = append(encryptedVsp, representative...)
	tag = append(tag, encryptedFsp...)
	httpRequest := generateHTTPRequestBeginning(tdRaw.decoySpec.GetHostname())

	// get current TLS keystream to write payload into the ciphertext of http request
	keystreamOffset := len(httpRequest)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	wholeKeystream, err := tdRaw.tlsConn.GetOutKeystream(keystreamSize)
	if err != nil {
		return nil, err
	}
	keystreamAtTag := wholeKeystream[keystreamOffset:]
	httpRequest = append(httpRequest, reverseEncrypt(tag, keystreamAtTag)...)

	if tdRaw.tagType == tagHttpGetComplete {
		httpRequest = append(httpRequest, []byte("\r\n\r\n")...)
	} else {
		httpRequest = append(httpRequest, []byte("what")...)
		tdRaw.UploadLimit = int(tdRaw.decoySpec.GetTcpwin()) - getRandInt(1, 1045)
	}
	return httpRequest, nil
}

func (tdRaw *tdRawConn) idStr() string {
	return "[Session " + strconv.FormatUint(tdRaw.sessionId, 10) + ", " +
		"Flow " + strconv.FormatUint(tdRaw.flowId, 10) + tdRaw.strIdSuffix + "]"
}

// Simply reads and returns protobuf
// Returns error if it's not a protobuf
// TODO: redesign it pb, data, err
func (tdRaw *tdRawConn) readProto() (msg pb.StationToClient, err error) {
	var readBuffer bytes.Buffer

	var outerProtoMsgType msgType
	var msgLen int64 // just the body (e.g. raw data or protobuf)

	// Get TIL
	_, err = io.CopyN(&readBuffer, tdRaw.tlsConn, 2)
	if err != nil {
		return
	}

	typeLen := uint16toInt16(binary.BigEndian.Uint16(readBuffer.Next(2)))
	if typeLen < 0 {
		outerProtoMsgType = msgRawData
		msgLen = int64(-typeLen)
	} else if typeLen > 0 {
		outerProtoMsgType = msgProtobuf
		msgLen = int64(typeLen)
	} else {
		// protobuf with size over 32KB, not fitting into 2-byte TL
		outerProtoMsgType = msgProtobuf
		_, err = io.CopyN(&readBuffer, tdRaw.tlsConn, 4)
		if err != nil {
			return
		}
		msgLen = int64(binary.BigEndian.Uint32(readBuffer.Next(4)))
	}

	if outerProtoMsgType == msgRawData {
		err = errors.New("Received data message in uninitialized flow")
		return
	}

	// Get the message itself
	_, err = io.CopyN(&readBuffer, tdRaw.tlsConn, msgLen)
	if err != nil {
		return
	}

	err = proto.Unmarshal(readBuffer.Bytes(), &msg)
	if err != nil {
		return
	}

	Logger().Debugln(tdRaw.idStr() + " INIT: received protobuf: " + msg.String())
	return
}

// Generates padding and stuff
// Currently guaranteed to be less than 1024 bytes long
func (tdRaw *tdRawConn) writeTransition(transition pb.C2S_Transition) (n int, err error) {
	const paddingMinSize = 250
	const paddingMaxSize = 800
	const paddingSmoothness = 5
	paddingDecrement := 0 // reduce potential padding size by this value

	currGen := Assets().GetGeneration()
	msg := pb.ClientToStation{
		DecoyListGeneration: &currGen,
		StateTransition:     &transition,
		UploadSync:          new(uint64)} // TODO: remove
	if tdRaw.flowId == 0 {
		// we have stats for each reconnect, but only send stats for the initial connection
		msg.Stats = &tdRaw.sessionStats
	}

	if len(tdRaw.failedDecoys) > 0 {
		failedDecoysIdx := 0 // how many failed decoys to report now
		for failedDecoysIdx < len(tdRaw.failedDecoys) {
			if paddingMinSize < proto.Size(&pb.ClientToStation{
				FailedDecoys: tdRaw.failedDecoys[:failedDecoysIdx+1]}) {
				// if failedDecoys list is too big to fit in place of min padding
				// then send the rest on the next reconnect
				break
			}
			failedDecoysIdx += 1
		}
		paddingDecrement = proto.Size(&pb.ClientToStation{
			FailedDecoys: tdRaw.failedDecoys[:failedDecoysIdx]})

		msg.FailedDecoys = tdRaw.failedDecoys[:failedDecoysIdx]
		tdRaw.failedDecoys = tdRaw.failedDecoys[failedDecoysIdx:]
	}
	msg.Padding = []byte(getRandPadding(paddingMinSize-paddingDecrement,
		paddingMaxSize-paddingDecrement, paddingSmoothness))

	msgBytes, err := proto.Marshal(&msg)
	if err != nil {
		return
	}

	Logger().Infoln(tdRaw.idStr()+" sending transition: ", msg.String())
	b := getMsgWithHeader(msgProtobuf, msgBytes)
	n, err = tdRaw.tlsConn.Write(b)
	return
}

func (tdRaw *tdRawConn) IsClosed() bool {
	select {
	case <-tdRaw.closed:
		return true
	default:
		return false
	}
}
