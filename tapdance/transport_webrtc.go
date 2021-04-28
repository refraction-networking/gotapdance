package tapdance

import (
	"crypto/sha256"
	"net"
	"os"

	randutil "github.com/Gaukas/randutil_kai"
	s2s "github.com/Gaukas/seed2sdp"
	webrtc "github.com/pion/webrtc/v3"
	"golang.org/x/crypto/hkdf"
)

type webrtcTransport struct {
	DataChannel *s2s.DataChannel
	Seed        string
}

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

func (wt *webrtcTransport) setWebrtcSeed(seed string) {
	wt.Seed = seed
}

func (wt *webrtcTransport) webrtcSeed() (string, error) {
	if len(wt.Seed) != 0 {
		return wt.Seed, nil
	}
	tempSeed, err := randutil.GenerateCryptoRandomString(lenSeed, runesAlpha+runesDigit)
	if err != nil {
		return "", err
	}
	wt.Seed = tempSeed
	return wt.Seed, nil
}

// Select one IP from IPList
func (wt *webrtcTransport) webrtcSelectIP(IPList []net.IP) net.IP {
	seed, _ := wt.webrtcSeed()
	ipReader := hkdf.New(sha256.New, []byte(conjureSecret), []byte(seed), []byte(ipHKDF))
	ipGen := randutil.NewReaderMathRandomGenerator(ipReader)

	return IPList[ipGen.Intn(len(IPList))]
}

// Select port in [low, high)
func (wt *webrtcTransport) webrtcSelectPort(low int, high int) uint16 {
	seed, _ := wt.webrtcSeed()
	portReader := hkdf.New(sha256.New, []byte(conjureSecret), []byte(seed), []byte(portHKDF))
	portGen := randutil.NewReaderMathRandomGenerator(portReader)

	return uint16(low + portGen.Intn(high-low))
}

// TO-DO: Finish callback handlers as a client
func (wt *webrtcTransport) webrtcSetCallbackHandlers() {
	// Called when Peer Connection state changes
	wt.DataChannel.WebRTCPeerConnection.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
		Logger().Warnf("Peer Connection changed state to: %s\n", connectionState.String())
		if connectionState.String() == "disconnected" || connectionState.String() == "closed" {
			Logger().Infof("Peer Connection disconnected\n")
			Logger().Infof("Shutting down...\n")
			os.Exit(0)
		}
	})

	// Called when datachannel is established
	wt.DataChannel.WebRTCDataChannel.OnOpen(func() {
		Logger().Infof("Successfully opened Data Channel '%s'-'%d'. \n", wt.DataChannel.WebRTCDataChannel.Label(), wt.DataChannel.WebRTCDataChannel.ID())
	})

	// Called when receive message from peer
	wt.DataChannel.WebRTCDataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		Logger().Debugf("%s OnRecv: %d bytes\n", wt.DataChannel.WebRTCDataChannel.Label(), len(msg.Data))
		// TO-DO: Handle the msg.Data as a transport interface
	})

	// Called when Data Channel is closed (by peer)
	wt.DataChannel.WebRTCDataChannel.OnClose(func() {
		Logger().Warnf("Data Channel %s closed\n", wt.DataChannel.WebRTCDataChannel.Label())
		Logger().Debugf("Tearing down Peer Connection due to closed datachannel\n")
		wt.DataChannel.WebRTCPeerConnection.Close()
	})

	// Called when there is a Data Channel layer error (not peer connection). Safe to tear down connection.
	wt.DataChannel.WebRTCDataChannel.OnError(func(err error) {
		Logger().Errorf("[Fatal] Data Channel %s errored: %v\n", wt.DataChannel.WebRTCDataChannel.Label(), err)
		Logger().Debugf("Tearing down Peer Connection due to error in datachannel\n")
		wt.DataChannel.WebRTCPeerConnection.Close()
	})
}

// webrtcPreRegister returns an SDPDeflated struct and a string seed.
// Both need to be exchanged in registration.
func (wt *webrtcTransport) webrtcPreRegister(ClientIP net.IP) (s2s.SDPDeflated, string) {
	seed, _ := wt.webrtcSeed()
	clientHkdfParams := s2s.NewHKDFParams().SetSecret(conjureSecret).SetSalt(seed).SetInfoPrefix(clientHKDF)
	serverHkdfParams := s2s.NewHKDFParams().SetSecret(conjureSecret).SetSalt(seed).SetInfoPrefix(serverHKDF)

	wt.DataChannel = s2s.DeclareDatachannel(
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
	if wt.DataChannel.Initialize() != nil {
		Logger().Error("Client failed to initialize a data channel instance.")
		panic("DataChannel.Initialize() unsuccessful.")
	}

	wt.webrtcSetCallbackHandlers()

	// Block until Offer is ready to exchange. (Not connecting to any peer yet)
	if wt.DataChannel.CreateOffer() != nil {
		Logger().Error("Client failed to create SDP offer.")
		panic("DataChannel.CreateOffer() unsuccessful.")
	}

	JsonOffer := s2s.ToJSON(wt.DataChannel.GetLocalDescription())
	ParsedOffer := s2s.ParseSDP(JsonOffer)
	DeflatedOffer := ParsedOffer.Deflate(ClientIP)
	return DeflatedOffer, seed
	// return s2s.ParseSDP(s2s.ToJSON(wt.DataChannel.GetLocalDescription())).Deflate(ClientIP)
}

// webrtcPostRegister establishs the peer connection & data channel.
// calling this function will trigger IMMEDIATE communication with server
// Advice: sleep for several seconds after registration, due to unstable ICE response time
func (wt *webrtcTransport) webrtcPostRegister(IPList []net.IP) {
	AnswerCandidateHost := s2s.ICECandidate{}
	AnswerCandidateHost.
		SetComponent(s2s.ICEComponentRTP).SetProtocol(s2s.UDP).
		SetIpAddr(wt.webrtcSelectIP(IPList)).SetPort(wt.webrtcSelectPort(portLow, portHigh)).
		SetCandidateType(s2s.Host)

	err := wt.DataChannel.SetAnswer([]s2s.ICECandidate{AnswerCandidateHost})
	if err != nil {
		Logger().Error("Client failed to set SDP answer.")
		panic(err)
	}
}

func (wt *webrtcTransport) webrtcSend(data []byte) {
	for !wt.DataChannel.ReadyToSend() {
		// fmt.Println("[Info] Data Channel not ready...")
	} // Always wait for ready to send
	Logger().Debugf("Sending %d Bytes via %s\n", len(data), wt.DataChannel.WebRTCDataChannel.Label())
	sendErr := wt.DataChannel.Send(data)
	if sendErr != nil {
		Logger().Errorf("Error in webrtcSend(), sending %d Bytes unsuccessful.", len(data))
		panic(sendErr)
	}
}
