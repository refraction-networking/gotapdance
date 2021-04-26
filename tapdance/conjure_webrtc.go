package tapdance

import (
	"crypto/sha256"
	"net"
	"os"

	randutil "github.com/Gaukas/randutil_kai"
	s2s "github.com/Gaukas/seed2sdp"
	"github.com/pion/webrtc"
	"golang.org/x/crypto/hkdf"
)

var conjureDataChannel *s2s.DataChannel = nil
var conjureWebRTCSeed string = ""

const (
	runesAlpha string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	runesDigit string = "0123456789"

	conjureSecret string = "ConjureConjureConjureConjure"
	clientHKDF    string = "0xBEEF"
	serverHKDF    string = "0xABEE"

	ipHKDF   string = "PHANTOMIP"
	portHKDF string = "PHANTOMPORT"

	lenSeed              = 64
	portLow       int    = 10000
	portHigh      int    = 65535
	txBufferLimit uint64 = 33554432 // Buffer: 32 M
)

func setWebrtcSeed(seed string) {
	conjureWebRTCSeed = seed
}

func webrtcSeed() (string, error) {
	if len(conjureWebRTCSeed) != 0 {
		return conjureWebRTCSeed, nil
	}
	tempSeed, err := randutil.GenerateCryptoRandomString(lenSeed, runesAlpha+runesDigit)
	if err != nil {
		return "", err
	}
	conjureWebRTCSeed = tempSeed
	return conjureWebRTCSeed, nil
}

// Select one IP from IPList
func webrtcSelectIP(IPList []net.IP) net.IP {
	seed, _ := webrtcSeed()
	ipReader := hkdf.New(sha256.New, []byte(conjureSecret), []byte(seed), []byte(ipHKDF))
	ipGen := randutil.NewReaderMathRandomGenerator(ipReader)

	return IPList[ipGen.Intn(len(IPList))]
}

// Select port in [low, high)
func webrtcSelectPort(low int, high int) int {
	seed, _ := webrtcSeed()
	portReader := hkdf.New(sha256.New, []byte(conjureSecret), []byte(seed), []byte(portHKDF))
	portGen := randutil.NewReaderMathRandomGenerator(portReader)

	return low + portGen.Intn(high-low)
}

// TO-DO: Finish callback handlers as a client
func webrtcSetCallbackHandlers() {
	// Called when Peer Connection state changes
	conjureDataChannel.WebRTCPeerConnection.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
		Logger().Warnf("Peer Connection changed state to: %s\n", connectionState.String())
		if connectionState.String() == "disconnected" || connectionState.String() == "closed" {
			Logger().Infof("Peer Connection disconnected\n")
			Logger().Infof("Shutting down...\n")
			os.Exit(0)
		}
	})

	// Called when datachannel is established
	conjureDataChannel.WebRTCDataChannel.OnOpen(func() {
		Logger().Infof("Successfully opened Data Channel '%s'-'%d'. \n", conjureDataChannel.WebRTCDataChannel.Label(), conjureDataChannel.WebRTCDataChannel.ID())
	})

	// Called when receive message from peer
	conjureDataChannel.WebRTCDataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		Logger().Debugf("%s OnRecv: %d bytes\n", conjureDataChannel.WebRTCDataChannel.Label(), len(msg.Data))
		// TO-DO: Handle the msg.Data as a transport interface
	})

	// Called when Data Channel is closed (by peer)
	conjureDataChannel.WebRTCDataChannel.OnClose(func() {
		Logger().Warnf("Data Channel %s closed\n", conjureDataChannel.WebRTCDataChannel.Label())
		Logger().Debugf("Tearing down Peer Connection due to closed datachannel\n")
		conjureDataChannel.WebRTCPeerConnection.Close()
	})

	// Called when there is a Data Channel layer error (not peer connection). Safe to tear down connection.
	conjureDataChannel.WebRTCDataChannel.OnError(func(err error) {
		Logger().Errorf("[Fatal] Data Channel %s errored: %v\n", conjureDataChannel.WebRTCDataChannel.Label(), err)
		Logger().Debugf("Tearing down Peer Connection due to error in datachannel\n")
		conjureDataChannel.WebRTCPeerConnection.Close()
	})
}

// webrtcPreRegister returns an SDPDeflated struct
// It needs to be exchanged in registration.
func webrtcPreRegister(ClientIP net.IP) s2s.SDPDeflated {
	seed, _ := webrtcSeed()
	clientHkdfParams := s2s.NewHKDFParams().SetSecret(conjureSecret).SetSalt(seed).SetInfoPrefix(clientHKDF)
	serverHkdfParams := s2s.NewHKDFParams().SetSecret(conjureSecret).SetSalt(seed).SetInfoPrefix(serverHKDF)

	conjureDataChannel = s2s.DeclareDatachannel(
		&s2s.DataChannelConfig{
			Label:          "Conjure DataChannel - Client Owned",
			SelfSDPType:    "offer",
			SelfHkdfParams: clientHkdfParams,
			PeerSDPType:    "answer",
			PeerHkdfParams: serverHkdfParams,
			PeerMedias: []s2s.SDPMedia{
				{
					MediaType:   "application",
					Description: "9 UDP/DTLS/SCTP webrtc-datachannel",
				},
			},
			PeerAttributes: []s2s.SDPAttribute{
				{
					Key:   "group",
					Value: "BUNDLE 0",
				},
				{
					Key:   "setup",
					Value: "active",
				},
				{
					Key:   "mid",
					Value: "0",
				},
				{
					Value: "sendrecv", // Transceivers
				},
				{
					Key:   "sctp-port",
					Value: "5000",
				},
			},
			TxBufferSize: txBufferLimit,
		},
	)

	// Block until DataChannel is created. (Not connecting to any peer yet)
	if conjureDataChannel.Initialize() != nil {
		Logger().Error("Client failed to initialize a data channel instance.")
		panic("DataChannel.Initialize() unsuccessful.")
	}

	webrtcSetCallbackHandlers()

	// Block until Offer is ready to exchange. (Not connecting to any peer yet)
	if conjureDataChannel.CreateOffer() != nil {
		Logger().Error("Client failed to create SDP offer.")
		panic("DataChannel.CreateOffer() unsuccessful.")
	}

	// JsonOffer := s2s.ToJSON(dataChannel.GetLocalDescription())
	// ParsedOffer := s2s.ParseSDP(JsonOffer)
	// DeflatedOffer := ParsedOffer.Deflate(MyPublicIP(v4))
	// return DeflatedOffer
	return s2s.ParseSDP(s2s.ToJSON(conjureDataChannel.GetLocalDescription())).Deflate(ClientIP)
}

// webrtcPostRegister establishs the peer connection & data channel.
// calling this function will trigger IMMEDIATE communication with server
// Advice: sleep for several seconds after registration, due to unstable ICE response time
func webrtcPostRegister(IPList []net.IP) {
	AnswerCandidateHost := s2s.ICECandidate{}
	AnswerCandidateHost.
		SetComponent(s2s.ICEComponentRTP).SetProtocol(s2s.UDP).
		SetIpAddr(webrtcSelectIP(IPList)).SetPort(webrtcSelectPort(portLow, portHigh)).
		SetCandidateType(s2s.Host)

	err := conjureDataChannel.SetAnswer([]s2s.ICECandidate{AnswerCandidateHost})
	if err != nil {
		Logger().Error("Client failed to set SDP answer.")
		panic(err)
	}
}

func webrtcSend(data []byte) {
	for !conjureDataChannel.ReadyToSend() {
		// fmt.Println("[Info] Data Channel not ready...")
	} // Always wait for ready to send
	Logger().Debugf("Sending %d Bytes via %s\n", len(data), conjureDataChannel.WebRTCDataChannel.Label())
	sendErr := conjureDataChannel.Send(data)
	if sendErr != nil {
		Logger().Errorf("Error in webrtcSend(), sending %d Bytes unsuccessful.", len(data))
		panic(sendErr)
	}
}
