// Code generated by protoc-gen-go. DO NOT EDIT.
// source: signalling.proto

package tdproto

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type KeyType int32

const (
	KeyType_AES_GCM_128 KeyType = 90
	KeyType_AES_GCM_256 KeyType = 91
)

var KeyType_name = map[int32]string{
	90: "AES_GCM_128",
	91: "AES_GCM_256",
}

var KeyType_value = map[string]int32{
	"AES_GCM_128": 90,
	"AES_GCM_256": 91,
}

func (x KeyType) Enum() *KeyType {
	p := new(KeyType)
	*p = x
	return p
}

func (x KeyType) String() string {
	return proto.EnumName(KeyType_name, int32(x))
}

func (x *KeyType) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(KeyType_value, data, "KeyType")
	if err != nil {
		return err
	}
	*x = KeyType(value)
	return nil
}

func (KeyType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{0}
}

// State transitions of the client
type C2S_Transition int32

const (
	C2S_Transition_C2S_NO_CHANGE                C2S_Transition = 0
	C2S_Transition_C2S_SESSION_INIT             C2S_Transition = 1
	C2S_Transition_C2S_SESSION_COVERT_INIT      C2S_Transition = 11
	C2S_Transition_C2S_EXPECT_RECONNECT         C2S_Transition = 2
	C2S_Transition_C2S_SESSION_CLOSE            C2S_Transition = 3
	C2S_Transition_C2S_YIELD_UPLOAD             C2S_Transition = 4
	C2S_Transition_C2S_ACQUIRE_UPLOAD           C2S_Transition = 5
	C2S_Transition_C2S_EXPECT_UPLOADONLY_RECONN C2S_Transition = 6
	C2S_Transition_C2S_ERROR                    C2S_Transition = 255
)

var C2S_Transition_name = map[int32]string{
	0:   "C2S_NO_CHANGE",
	1:   "C2S_SESSION_INIT",
	11:  "C2S_SESSION_COVERT_INIT",
	2:   "C2S_EXPECT_RECONNECT",
	3:   "C2S_SESSION_CLOSE",
	4:   "C2S_YIELD_UPLOAD",
	5:   "C2S_ACQUIRE_UPLOAD",
	6:   "C2S_EXPECT_UPLOADONLY_RECONN",
	255: "C2S_ERROR",
}

var C2S_Transition_value = map[string]int32{
	"C2S_NO_CHANGE":                0,
	"C2S_SESSION_INIT":             1,
	"C2S_SESSION_COVERT_INIT":      11,
	"C2S_EXPECT_RECONNECT":         2,
	"C2S_SESSION_CLOSE":            3,
	"C2S_YIELD_UPLOAD":             4,
	"C2S_ACQUIRE_UPLOAD":           5,
	"C2S_EXPECT_UPLOADONLY_RECONN": 6,
	"C2S_ERROR":                    255,
}

func (x C2S_Transition) Enum() *C2S_Transition {
	p := new(C2S_Transition)
	*p = x
	return p
}

func (x C2S_Transition) String() string {
	return proto.EnumName(C2S_Transition_name, int32(x))
}

func (x *C2S_Transition) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(C2S_Transition_value, data, "C2S_Transition")
	if err != nil {
		return err
	}
	*x = C2S_Transition(value)
	return nil
}

func (C2S_Transition) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{1}
}

// State transitions of the server
type S2C_Transition int32

const (
	S2C_Transition_S2C_NO_CHANGE           S2C_Transition = 0
	S2C_Transition_S2C_SESSION_INIT        S2C_Transition = 1
	S2C_Transition_S2C_SESSION_COVERT_INIT S2C_Transition = 11
	S2C_Transition_S2C_CONFIRM_RECONNECT   S2C_Transition = 2
	S2C_Transition_S2C_SESSION_CLOSE       S2C_Transition = 3
	// TODO should probably also allow EXPECT_RECONNECT here, for DittoTap
	S2C_Transition_S2C_ERROR S2C_Transition = 255
)

var S2C_Transition_name = map[int32]string{
	0:   "S2C_NO_CHANGE",
	1:   "S2C_SESSION_INIT",
	11:  "S2C_SESSION_COVERT_INIT",
	2:   "S2C_CONFIRM_RECONNECT",
	3:   "S2C_SESSION_CLOSE",
	255: "S2C_ERROR",
}

var S2C_Transition_value = map[string]int32{
	"S2C_NO_CHANGE":           0,
	"S2C_SESSION_INIT":        1,
	"S2C_SESSION_COVERT_INIT": 11,
	"S2C_CONFIRM_RECONNECT":   2,
	"S2C_SESSION_CLOSE":       3,
	"S2C_ERROR":               255,
}

func (x S2C_Transition) Enum() *S2C_Transition {
	p := new(S2C_Transition)
	*p = x
	return p
}

func (x S2C_Transition) String() string {
	return proto.EnumName(S2C_Transition_name, int32(x))
}

func (x *S2C_Transition) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(S2C_Transition_value, data, "S2C_Transition")
	if err != nil {
		return err
	}
	*x = S2C_Transition(value)
	return nil
}

func (S2C_Transition) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{2}
}

// Should accompany all S2C_ERROR messages.
type ErrorReasonS2C int32

const (
	ErrorReasonS2C_NO_ERROR         ErrorReasonS2C = 0
	ErrorReasonS2C_COVERT_STREAM    ErrorReasonS2C = 1
	ErrorReasonS2C_CLIENT_REPORTED  ErrorReasonS2C = 2
	ErrorReasonS2C_CLIENT_PROTOCOL  ErrorReasonS2C = 3
	ErrorReasonS2C_STATION_INTERNAL ErrorReasonS2C = 4
	ErrorReasonS2C_DECOY_OVERLOAD   ErrorReasonS2C = 5
	ErrorReasonS2C_CLIENT_STREAM    ErrorReasonS2C = 100
	ErrorReasonS2C_CLIENT_TIMEOUT   ErrorReasonS2C = 101
)

var ErrorReasonS2C_name = map[int32]string{
	0:   "NO_ERROR",
	1:   "COVERT_STREAM",
	2:   "CLIENT_REPORTED",
	3:   "CLIENT_PROTOCOL",
	4:   "STATION_INTERNAL",
	5:   "DECOY_OVERLOAD",
	100: "CLIENT_STREAM",
	101: "CLIENT_TIMEOUT",
}

var ErrorReasonS2C_value = map[string]int32{
	"NO_ERROR":         0,
	"COVERT_STREAM":    1,
	"CLIENT_REPORTED":  2,
	"CLIENT_PROTOCOL":  3,
	"STATION_INTERNAL": 4,
	"DECOY_OVERLOAD":   5,
	"CLIENT_STREAM":    100,
	"CLIENT_TIMEOUT":   101,
}

func (x ErrorReasonS2C) Enum() *ErrorReasonS2C {
	p := new(ErrorReasonS2C)
	*p = x
	return p
}

func (x ErrorReasonS2C) String() string {
	return proto.EnumName(ErrorReasonS2C_name, int32(x))
}

func (x *ErrorReasonS2C) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(ErrorReasonS2C_value, data, "ErrorReasonS2C")
	if err != nil {
		return err
	}
	*x = ErrorReasonS2C(value)
	return nil
}

func (ErrorReasonS2C) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{3}
}

type PubKey struct {
	// A public key, as used by the station.
	Key                  []byte   `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Type                 *KeyType `protobuf:"varint,2,opt,name=type,enum=tapdance.KeyType" json:"type,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PubKey) Reset()         { *m = PubKey{} }
func (m *PubKey) String() string { return proto.CompactTextString(m) }
func (*PubKey) ProtoMessage()    {}
func (*PubKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{0}
}

func (m *PubKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PubKey.Unmarshal(m, b)
}
func (m *PubKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PubKey.Marshal(b, m, deterministic)
}
func (m *PubKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PubKey.Merge(m, src)
}
func (m *PubKey) XXX_Size() int {
	return xxx_messageInfo_PubKey.Size(m)
}
func (m *PubKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PubKey.DiscardUnknown(m)
}

var xxx_messageInfo_PubKey proto.InternalMessageInfo

func (m *PubKey) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *PubKey) GetType() KeyType {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return KeyType_AES_GCM_128
}

type TLSDecoySpec struct {
	// The hostname/SNI to use for this host
	//
	// The hostname is the only required field, although other
	// fields are expected to be present in most cases.
	Hostname *string `protobuf:"bytes,1,opt,name=hostname" json:"hostname,omitempty"`
	// The 32-bit ipv4 address, in network byte order
	//
	// If the IPv4 address is absent, then it may be resolved via
	// DNS by the client, or the client may discard this decoy spec
	// if local DNS is untrusted, or the service may be multihomed.
	Ipv4Addr *uint32 `protobuf:"fixed32,2,opt,name=ipv4addr" json:"ipv4addr,omitempty"`
	// The 128-bit ipv6 address, in network byte order
	Ipv6Addr []byte `protobuf:"bytes,6,opt,name=ipv6addr" json:"ipv6addr,omitempty"`
	// The Tapdance station public key to use when contacting this
	// decoy
	//
	// If omitted, the default station public key (if any) is used.
	Pubkey *PubKey `protobuf:"bytes,3,opt,name=pubkey" json:"pubkey,omitempty"`
	// The maximum duration, in milliseconds, to maintain an open
	// connection to this decoy (because the decoy may close the
	// connection itself after this length of time)
	//
	// If omitted, a default of 30,000 milliseconds is assumed.
	Timeout *uint32 `protobuf:"varint,4,opt,name=timeout" json:"timeout,omitempty"`
	// The maximum TCP window size to attempt to use for this decoy.
	//
	// If omitted, a default of 15360 is assumed.
	//
	// TODO: the default is based on the current heuristic of only
	// using decoys that permit windows of 15KB or larger.  If this
	// heuristic changes, then this default doesn't make sense.
	Tcpwin               *uint32  `protobuf:"varint,5,opt,name=tcpwin" json:"tcpwin,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TLSDecoySpec) Reset()         { *m = TLSDecoySpec{} }
func (m *TLSDecoySpec) String() string { return proto.CompactTextString(m) }
func (*TLSDecoySpec) ProtoMessage()    {}
func (*TLSDecoySpec) Descriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{1}
}

func (m *TLSDecoySpec) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TLSDecoySpec.Unmarshal(m, b)
}
func (m *TLSDecoySpec) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TLSDecoySpec.Marshal(b, m, deterministic)
}
func (m *TLSDecoySpec) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TLSDecoySpec.Merge(m, src)
}
func (m *TLSDecoySpec) XXX_Size() int {
	return xxx_messageInfo_TLSDecoySpec.Size(m)
}
func (m *TLSDecoySpec) XXX_DiscardUnknown() {
	xxx_messageInfo_TLSDecoySpec.DiscardUnknown(m)
}

var xxx_messageInfo_TLSDecoySpec proto.InternalMessageInfo

func (m *TLSDecoySpec) GetHostname() string {
	if m != nil && m.Hostname != nil {
		return *m.Hostname
	}
	return ""
}

func (m *TLSDecoySpec) GetIpv4Addr() uint32 {
	if m != nil && m.Ipv4Addr != nil {
		return *m.Ipv4Addr
	}
	return 0
}

func (m *TLSDecoySpec) GetIpv6Addr() []byte {
	if m != nil {
		return m.Ipv6Addr
	}
	return nil
}

func (m *TLSDecoySpec) GetPubkey() *PubKey {
	if m != nil {
		return m.Pubkey
	}
	return nil
}

func (m *TLSDecoySpec) GetTimeout() uint32 {
	if m != nil && m.Timeout != nil {
		return *m.Timeout
	}
	return 0
}

func (m *TLSDecoySpec) GetTcpwin() uint32 {
	if m != nil && m.Tcpwin != nil {
		return *m.Tcpwin
	}
	return 0
}

type ClientConf struct {
	DecoyList            *DecoyList `protobuf:"bytes,1,opt,name=decoy_list,json=decoyList" json:"decoy_list,omitempty"`
	Generation           *uint32    `protobuf:"varint,2,opt,name=generation" json:"generation,omitempty"`
	DefaultPubkey        *PubKey    `protobuf:"bytes,3,opt,name=default_pubkey,json=defaultPubkey" json:"default_pubkey,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *ClientConf) Reset()         { *m = ClientConf{} }
func (m *ClientConf) String() string { return proto.CompactTextString(m) }
func (*ClientConf) ProtoMessage()    {}
func (*ClientConf) Descriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{2}
}

func (m *ClientConf) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientConf.Unmarshal(m, b)
}
func (m *ClientConf) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientConf.Marshal(b, m, deterministic)
}
func (m *ClientConf) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientConf.Merge(m, src)
}
func (m *ClientConf) XXX_Size() int {
	return xxx_messageInfo_ClientConf.Size(m)
}
func (m *ClientConf) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientConf.DiscardUnknown(m)
}

var xxx_messageInfo_ClientConf proto.InternalMessageInfo

func (m *ClientConf) GetDecoyList() *DecoyList {
	if m != nil {
		return m.DecoyList
	}
	return nil
}

func (m *ClientConf) GetGeneration() uint32 {
	if m != nil && m.Generation != nil {
		return *m.Generation
	}
	return 0
}

func (m *ClientConf) GetDefaultPubkey() *PubKey {
	if m != nil {
		return m.DefaultPubkey
	}
	return nil
}

type DecoyList struct {
	TlsDecoys            []*TLSDecoySpec `protobuf:"bytes,1,rep,name=tls_decoys,json=tlsDecoys" json:"tls_decoys,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *DecoyList) Reset()         { *m = DecoyList{} }
func (m *DecoyList) String() string { return proto.CompactTextString(m) }
func (*DecoyList) ProtoMessage()    {}
func (*DecoyList) Descriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{3}
}

func (m *DecoyList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DecoyList.Unmarshal(m, b)
}
func (m *DecoyList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DecoyList.Marshal(b, m, deterministic)
}
func (m *DecoyList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DecoyList.Merge(m, src)
}
func (m *DecoyList) XXX_Size() int {
	return xxx_messageInfo_DecoyList.Size(m)
}
func (m *DecoyList) XXX_DiscardUnknown() {
	xxx_messageInfo_DecoyList.DiscardUnknown(m)
}

var xxx_messageInfo_DecoyList proto.InternalMessageInfo

func (m *DecoyList) GetTlsDecoys() []*TLSDecoySpec {
	if m != nil {
		return m.TlsDecoys
	}
	return nil
}

type StationToClient struct {
	// Should accompany (at least) SESSION_INIT and CONFIRM_RECONNECT.
	ProtocolVersion *uint32 `protobuf:"varint,1,opt,name=protocol_version,json=protocolVersion" json:"protocol_version,omitempty"`
	// There might be a state transition. May be absent; absence should be
	// treated identically to NO_CHANGE.
	StateTransition *S2C_Transition `protobuf:"varint,2,opt,name=state_transition,json=stateTransition,enum=tapdance.S2C_Transition" json:"state_transition,omitempty"`
	// The station can send client config info piggybacked
	// on any message, as it sees fit
	ConfigInfo *ClientConf `protobuf:"bytes,3,opt,name=config_info,json=configInfo" json:"config_info,omitempty"`
	// If state_transition == S2C_ERROR, this field is the explanation.
	ErrReason *ErrorReasonS2C `protobuf:"varint,4,opt,name=err_reason,json=errReason,enum=tapdance.ErrorReasonS2C" json:"err_reason,omitempty"`
	// Signals client to stop connecting for following amount of seconds
	TmpBackoff *uint32 `protobuf:"varint,5,opt,name=tmp_backoff,json=tmpBackoff" json:"tmp_backoff,omitempty"`
	// Sent in SESSION_INIT, identifies the station that picked up
	StationId *string `protobuf:"bytes,6,opt,name=station_id,json=stationId" json:"station_id,omitempty"`
	// Random-sized junk to defeat packet size fingerprinting.
	Padding              []byte   `protobuf:"bytes,100,opt,name=padding" json:"padding,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StationToClient) Reset()         { *m = StationToClient{} }
func (m *StationToClient) String() string { return proto.CompactTextString(m) }
func (*StationToClient) ProtoMessage()    {}
func (*StationToClient) Descriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{4}
}

func (m *StationToClient) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StationToClient.Unmarshal(m, b)
}
func (m *StationToClient) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StationToClient.Marshal(b, m, deterministic)
}
func (m *StationToClient) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StationToClient.Merge(m, src)
}
func (m *StationToClient) XXX_Size() int {
	return xxx_messageInfo_StationToClient.Size(m)
}
func (m *StationToClient) XXX_DiscardUnknown() {
	xxx_messageInfo_StationToClient.DiscardUnknown(m)
}

var xxx_messageInfo_StationToClient proto.InternalMessageInfo

func (m *StationToClient) GetProtocolVersion() uint32 {
	if m != nil && m.ProtocolVersion != nil {
		return *m.ProtocolVersion
	}
	return 0
}

func (m *StationToClient) GetStateTransition() S2C_Transition {
	if m != nil && m.StateTransition != nil {
		return *m.StateTransition
	}
	return S2C_Transition_S2C_NO_CHANGE
}

func (m *StationToClient) GetConfigInfo() *ClientConf {
	if m != nil {
		return m.ConfigInfo
	}
	return nil
}

func (m *StationToClient) GetErrReason() ErrorReasonS2C {
	if m != nil && m.ErrReason != nil {
		return *m.ErrReason
	}
	return ErrorReasonS2C_NO_ERROR
}

func (m *StationToClient) GetTmpBackoff() uint32 {
	if m != nil && m.TmpBackoff != nil {
		return *m.TmpBackoff
	}
	return 0
}

func (m *StationToClient) GetStationId() string {
	if m != nil && m.StationId != nil {
		return *m.StationId
	}
	return ""
}

func (m *StationToClient) GetPadding() []byte {
	if m != nil {
		return m.Padding
	}
	return nil
}

type ClientToStation struct {
	ProtocolVersion *uint32 `protobuf:"varint,1,opt,name=protocol_version,json=protocolVersion" json:"protocol_version,omitempty"`
	// The client reports its decoy list's version number here, which the
	// station can use to decide whether to send an updated one. The station
	// should always send a list if this field is set to 0.
	DecoyListGeneration *uint32         `protobuf:"varint,2,opt,name=decoy_list_generation,json=decoyListGeneration" json:"decoy_list_generation,omitempty"`
	StateTransition     *C2S_Transition `protobuf:"varint,3,opt,name=state_transition,json=stateTransition,enum=tapdance.C2S_Transition" json:"state_transition,omitempty"`
	// The position in the overall session's upload sequence where the current
	// YIELD=>ACQUIRE switchover is happening.
	UploadSync *uint64 `protobuf:"varint,4,opt,name=upload_sync,json=uploadSync" json:"upload_sync,omitempty"`
	// List of decoys that client have unsuccessfully tried in current session.
	// Could be sent in chunks
	FailedDecoys []string      `protobuf:"bytes,10,rep,name=failed_decoys,json=failedDecoys" json:"failed_decoys,omitempty"`
	Stats        *SessionStats `protobuf:"bytes,11,opt,name=stats" json:"stats,omitempty"`
	// Station is only required to check this variable during session initialization.
	// If set, station must facilitate connection to said target by itself, i.e. write into squid
	// socket an HTTP/SOCKS/any other connection request.
	// covert_address must have exactly one ':' colon, that separates host (literal IP address or
	// resolvable hostname) and port
	// TODO: make it required for initialization, and stop connecting any client straight to squid?
	CovertAddress *string `protobuf:"bytes,20,opt,name=covert_address,json=covertAddress" json:"covert_address,omitempty"`
	// Used in dark decoys to signal which dark decoy it will connect to.
	MaskedDecoyServerName *string `protobuf:"bytes,21,opt,name=masked_decoy_server_name,json=maskedDecoyServerName" json:"masked_decoy_server_name,omitempty"`
	// Used to indicate to server if client is registering v4, v6 or both
	V6Support *bool `protobuf:"varint,22,opt,name=v6_support,json=v6Support" json:"v6_support,omitempty"`
	V4Support *bool `protobuf:"varint,23,opt,name=v4_support,json=v4Support" json:"v4_support,omitempty"`
	// Random-sized junk to defeat packet size fingerprinting.
	Padding              []byte   `protobuf:"bytes,100,opt,name=padding" json:"padding,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientToStation) Reset()         { *m = ClientToStation{} }
func (m *ClientToStation) String() string { return proto.CompactTextString(m) }
func (*ClientToStation) ProtoMessage()    {}
func (*ClientToStation) Descriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{5}
}

func (m *ClientToStation) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientToStation.Unmarshal(m, b)
}
func (m *ClientToStation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientToStation.Marshal(b, m, deterministic)
}
func (m *ClientToStation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientToStation.Merge(m, src)
}
func (m *ClientToStation) XXX_Size() int {
	return xxx_messageInfo_ClientToStation.Size(m)
}
func (m *ClientToStation) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientToStation.DiscardUnknown(m)
}

var xxx_messageInfo_ClientToStation proto.InternalMessageInfo

func (m *ClientToStation) GetProtocolVersion() uint32 {
	if m != nil && m.ProtocolVersion != nil {
		return *m.ProtocolVersion
	}
	return 0
}

func (m *ClientToStation) GetDecoyListGeneration() uint32 {
	if m != nil && m.DecoyListGeneration != nil {
		return *m.DecoyListGeneration
	}
	return 0
}

func (m *ClientToStation) GetStateTransition() C2S_Transition {
	if m != nil && m.StateTransition != nil {
		return *m.StateTransition
	}
	return C2S_Transition_C2S_NO_CHANGE
}

func (m *ClientToStation) GetUploadSync() uint64 {
	if m != nil && m.UploadSync != nil {
		return *m.UploadSync
	}
	return 0
}

func (m *ClientToStation) GetFailedDecoys() []string {
	if m != nil {
		return m.FailedDecoys
	}
	return nil
}

func (m *ClientToStation) GetStats() *SessionStats {
	if m != nil {
		return m.Stats
	}
	return nil
}

func (m *ClientToStation) GetCovertAddress() string {
	if m != nil && m.CovertAddress != nil {
		return *m.CovertAddress
	}
	return ""
}

func (m *ClientToStation) GetMaskedDecoyServerName() string {
	if m != nil && m.MaskedDecoyServerName != nil {
		return *m.MaskedDecoyServerName
	}
	return ""
}

func (m *ClientToStation) GetV6Support() bool {
	if m != nil && m.V6Support != nil {
		return *m.V6Support
	}
	return false
}

func (m *ClientToStation) GetV4Support() bool {
	if m != nil && m.V4Support != nil {
		return *m.V4Support
	}
	return false
}

func (m *ClientToStation) GetPadding() []byte {
	if m != nil {
		return m.Padding
	}
	return nil
}

type SessionStats struct {
	FailedDecoysAmount *uint32 `protobuf:"varint,20,opt,name=failed_decoys_amount,json=failedDecoysAmount" json:"failed_decoys_amount,omitempty"`
	// Applicable to whole session:
	TotalTimeToConnect *uint32 `protobuf:"varint,31,opt,name=total_time_to_connect,json=totalTimeToConnect" json:"total_time_to_connect,omitempty"`
	// Last (i.e. successful) decoy:
	RttToStation         *uint32  `protobuf:"varint,33,opt,name=rtt_to_station,json=rttToStation" json:"rtt_to_station,omitempty"`
	TlsToDecoy           *uint32  `protobuf:"varint,38,opt,name=tls_to_decoy,json=tlsToDecoy" json:"tls_to_decoy,omitempty"`
	TcpToDecoy           *uint32  `protobuf:"varint,39,opt,name=tcp_to_decoy,json=tcpToDecoy" json:"tcp_to_decoy,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionStats) Reset()         { *m = SessionStats{} }
func (m *SessionStats) String() string { return proto.CompactTextString(m) }
func (*SessionStats) ProtoMessage()    {}
func (*SessionStats) Descriptor() ([]byte, []int) {
	return fileDescriptor_39f66308029891ad, []int{6}
}

func (m *SessionStats) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SessionStats.Unmarshal(m, b)
}
func (m *SessionStats) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SessionStats.Marshal(b, m, deterministic)
}
func (m *SessionStats) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionStats.Merge(m, src)
}
func (m *SessionStats) XXX_Size() int {
	return xxx_messageInfo_SessionStats.Size(m)
}
func (m *SessionStats) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionStats.DiscardUnknown(m)
}

var xxx_messageInfo_SessionStats proto.InternalMessageInfo

func (m *SessionStats) GetFailedDecoysAmount() uint32 {
	if m != nil && m.FailedDecoysAmount != nil {
		return *m.FailedDecoysAmount
	}
	return 0
}

func (m *SessionStats) GetTotalTimeToConnect() uint32 {
	if m != nil && m.TotalTimeToConnect != nil {
		return *m.TotalTimeToConnect
	}
	return 0
}

func (m *SessionStats) GetRttToStation() uint32 {
	if m != nil && m.RttToStation != nil {
		return *m.RttToStation
	}
	return 0
}

func (m *SessionStats) GetTlsToDecoy() uint32 {
	if m != nil && m.TlsToDecoy != nil {
		return *m.TlsToDecoy
	}
	return 0
}

func (m *SessionStats) GetTcpToDecoy() uint32 {
	if m != nil && m.TcpToDecoy != nil {
		return *m.TcpToDecoy
	}
	return 0
}

func init() {
	proto.RegisterEnum("tapdance.KeyType", KeyType_name, KeyType_value)
	proto.RegisterEnum("tapdance.C2S_Transition", C2S_Transition_name, C2S_Transition_value)
	proto.RegisterEnum("tapdance.S2C_Transition", S2C_Transition_name, S2C_Transition_value)
	proto.RegisterEnum("tapdance.ErrorReasonS2C", ErrorReasonS2C_name, ErrorReasonS2C_value)
	proto.RegisterType((*PubKey)(nil), "tapdance.PubKey")
	proto.RegisterType((*TLSDecoySpec)(nil), "tapdance.TLSDecoySpec")
	proto.RegisterType((*ClientConf)(nil), "tapdance.ClientConf")
	proto.RegisterType((*DecoyList)(nil), "tapdance.DecoyList")
	proto.RegisterType((*StationToClient)(nil), "tapdance.StationToClient")
	proto.RegisterType((*ClientToStation)(nil), "tapdance.ClientToStation")
	proto.RegisterType((*SessionStats)(nil), "tapdance.SessionStats")
}

func init() { proto.RegisterFile("signalling.proto", fileDescriptor_39f66308029891ad) }

var fileDescriptor_39f66308029891ad = []byte{
	// 1082 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0xdb, 0x72, 0xe3, 0x44,
	0x10, 0x5d, 0xc5, 0xd9, 0x6c, 0xdc, 0xbe, 0x69, 0x67, 0xe3, 0xac, 0xb8, 0x2c, 0x31, 0x86, 0x05,
	0x13, 0xa8, 0x14, 0xab, 0xca, 0x85, 0x57, 0xaf, 0x22, 0x82, 0x6b, 0x1d, 0xc9, 0x8c, 0x94, 0x2d,
	0x02, 0x0f, 0x53, 0x8a, 0x34, 0x0e, 0xaa, 0xc8, 0x1a, 0x95, 0x34, 0x36, 0xe5, 0x3f, 0x81, 0x7f,
	0xe0, 0x1b, 0xf8, 0x01, 0xbe, 0x81, 0x07, 0x9e, 0xf8, 0x0c, 0xa8, 0x99, 0x91, 0x6f, 0x59, 0x2e,
	0xc5, 0x9b, 0xe6, 0x9c, 0xee, 0xe9, 0x3e, 0xdd, 0x47, 0x03, 0x7a, 0x11, 0xdf, 0xa6, 0x41, 0x92,
	0xc4, 0xe9, 0xed, 0x51, 0x96, 0x33, 0xce, 0xd0, 0x2e, 0x0f, 0xb2, 0x28, 0x48, 0x43, 0xda, 0xed,
	0xc3, 0xce, 0x68, 0x7a, 0xf3, 0x8a, 0xce, 0x91, 0x0e, 0x95, 0x3b, 0x3a, 0x37, 0xb4, 0x8e, 0xd6,
	0xab, 0x63, 0xf1, 0x89, 0x9e, 0xc3, 0x36, 0x9f, 0x67, 0xd4, 0xd8, 0xea, 0x68, 0xbd, 0xa6, 0xf9,
	0xf8, 0x68, 0x91, 0x74, 0xf4, 0x8a, 0xce, 0xfd, 0x79, 0x46, 0xb1, 0xa4, 0xbb, 0xbf, 0x68, 0x50,
	0xf7, 0x87, 0xde, 0x39, 0x0d, 0xd9, 0xdc, 0xcb, 0x68, 0x88, 0xde, 0x86, 0xdd, 0xef, 0x59, 0xc1,
	0xd3, 0x60, 0x42, 0xe5, 0x75, 0x55, 0xbc, 0x3c, 0x0b, 0x2e, 0xce, 0x66, 0xc7, 0x41, 0x14, 0xe5,
	0xf2, 0xde, 0x47, 0x78, 0x79, 0x2e, 0xb9, 0x53, 0xc9, 0xed, 0xc8, 0x36, 0x96, 0x67, 0xd4, 0x83,
	0x9d, 0x6c, 0x7a, 0x23, 0x1a, 0xac, 0x74, 0xb4, 0x5e, 0xcd, 0xd4, 0x57, 0xdd, 0xa8, 0xfe, 0x71,
	0xc9, 0x23, 0x03, 0x1e, 0xf1, 0x78, 0x42, 0xd9, 0x94, 0x1b, 0xdb, 0x1d, 0xad, 0xd7, 0xc0, 0x8b,
	0x23, 0xda, 0x87, 0x1d, 0x1e, 0x66, 0x3f, 0xc4, 0xa9, 0xf1, 0x50, 0x12, 0xe5, 0xa9, 0xfb, 0x93,
	0x06, 0x60, 0x25, 0x31, 0x4d, 0xb9, 0xc5, 0xd2, 0x31, 0x32, 0x01, 0x22, 0xa1, 0x85, 0x24, 0x71,
	0xc1, 0xa5, 0x80, 0x9a, 0xf9, 0x64, 0x55, 0x4e, 0xea, 0x1c, 0xc6, 0x05, 0xc7, 0xd5, 0x68, 0xf1,
	0x89, 0xde, 0x03, 0xb8, 0xa5, 0x29, 0xcd, 0x03, 0x1e, 0xb3, 0x54, 0x0a, 0x6b, 0xe0, 0x35, 0x04,
	0x9d, 0x41, 0x33, 0xa2, 0xe3, 0x60, 0x9a, 0x70, 0xf2, 0x1f, 0x32, 0x1a, 0x65, 0xdc, 0x48, 0x86,
	0x75, 0x5f, 0x42, 0x75, 0x59, 0x10, 0x9d, 0x00, 0xf0, 0xa4, 0x20, 0xb2, 0x6c, 0x61, 0x68, 0x9d,
	0x4a, 0xaf, 0x66, 0xee, 0xaf, 0x6e, 0x58, 0x5f, 0x02, 0xae, 0xf2, 0xa4, 0x90, 0xa7, 0xa2, 0xfb,
	0xeb, 0x16, 0xb4, 0x3c, 0x2e, 0x1b, 0xf1, 0x99, 0x12, 0x8a, 0x3e, 0x01, 0x5d, 0x5a, 0x21, 0x64,
	0x09, 0x99, 0xd1, 0xbc, 0x10, 0x6d, 0x6b, 0xb2, 0xed, 0xd6, 0x02, 0x7f, 0xad, 0x60, 0x64, 0x81,
	0x5e, 0xf0, 0x80, 0x53, 0xc2, 0xf3, 0x20, 0x2d, 0xe2, 0xa5, 0xc2, 0xa6, 0x69, 0xac, 0x6a, 0x7b,
	0xa6, 0x45, 0xfc, 0x25, 0x8f, 0x5b, 0x32, 0x63, 0x05, 0xa0, 0x13, 0xa8, 0x85, 0x2c, 0x1d, 0xc7,
	0xb7, 0x24, 0x4e, 0xc7, 0xac, 0x54, 0xbf, 0xb7, 0xca, 0x5f, 0xcd, 0x1f, 0x83, 0x0a, 0x1c, 0xa4,
	0x63, 0x86, 0xce, 0x00, 0x68, 0x9e, 0x93, 0x9c, 0x06, 0x05, 0x4b, 0xe5, 0x3e, 0x37, 0xaa, 0xda,
	0x79, 0xce, 0x72, 0x2c, 0x49, 0xcf, 0xb4, 0x70, 0x95, 0xe6, 0xe5, 0x09, 0x1d, 0x40, 0x8d, 0x4f,
	0x32, 0x72, 0x13, 0x84, 0x77, 0x6c, 0x3c, 0x2e, 0x17, 0x0e, 0x7c, 0x92, 0xbd, 0x54, 0x08, 0x7a,
	0x06, 0x50, 0xa8, 0x99, 0x90, 0x38, 0x92, 0x76, 0xab, 0xe2, 0x6a, 0x89, 0x0c, 0x22, 0xe1, 0xa2,
	0x2c, 0x88, 0xa2, 0x38, 0xbd, 0x35, 0x22, 0x69, 0xc5, 0xc5, 0xb1, 0xfb, 0x7b, 0x05, 0x5a, 0xaa,
	0x5b, 0x9f, 0x95, 0x53, 0xfd, 0x3f, 0xd3, 0x34, 0xa1, 0xbd, 0x72, 0x17, 0x79, 0xc3, 0x34, 0x4f,
	0x96, 0x9e, 0xba, 0x58, 0xb9, 0xe7, 0xef, 0x36, 0x50, 0xb9, 0x3f, 0x0b, 0xcb, 0xf4, 0xfe, 0x75,
	0x03, 0x07, 0x50, 0x9b, 0x66, 0x09, 0x0b, 0x22, 0x52, 0xcc, 0xd3, 0x50, 0xce, 0x72, 0x1b, 0x83,
	0x82, 0xbc, 0x79, 0x1a, 0xa2, 0x0f, 0xa0, 0x31, 0x0e, 0xe2, 0x84, 0x46, 0x0b, 0x83, 0x41, 0xa7,
	0xd2, 0xab, 0xe2, 0xba, 0x02, 0x95, 0x97, 0xd0, 0x67, 0xf0, 0x50, 0x5c, 0x5c, 0x18, 0x35, 0xb9,
	0xc1, 0x35, 0xf7, 0x79, 0xb4, 0x10, 0x02, 0xc5, 0x48, 0x0a, 0xac, 0x82, 0xd0, 0x73, 0x68, 0x86,
	0x6c, 0x46, 0x73, 0x4e, 0xc4, 0x4f, 0x4c, 0x8b, 0xc2, 0xd8, 0x93, 0x83, 0x6e, 0x28, 0xb4, 0xaf,
	0x40, 0x74, 0x06, 0xc6, 0x24, 0x28, 0xee, 0x16, 0x95, 0x49, 0x41, 0xf3, 0x19, 0xcd, 0x89, 0x7c,
	0x40, 0xda, 0x32, 0xa1, 0xad, 0x78, 0x65, 0x6f, 0xc9, 0x3a, 0xe2, 0x35, 0x79, 0x06, 0x30, 0x3b,
	0x25, 0xc5, 0x34, 0xcb, 0x58, 0xce, 0x8d, 0xfd, 0x8e, 0xd6, 0xdb, 0xc5, 0xd5, 0xd9, 0xa9, 0xa7,
	0x00, 0x49, 0x1f, 0x2f, 0xe9, 0xa7, 0x25, 0x7d, 0xbc, 0xa0, 0xff, 0x79, 0xc7, 0xbf, 0x69, 0x50,
	0x5f, 0xd7, 0x83, 0x3e, 0x87, 0xbd, 0x8d, 0xd9, 0x90, 0x60, 0xc2, 0xa6, 0x29, 0x97, 0x72, 0x1a,
	0x18, 0xad, 0x8f, 0xa8, 0x2f, 0x19, 0xf4, 0x02, 0xda, 0x9c, 0xf1, 0x20, 0x21, 0xe2, 0xf5, 0x21,
	0x9c, 0x91, 0x90, 0xa5, 0x29, 0x0d, 0xb9, 0x71, 0xa0, 0x52, 0x24, 0xe9, 0xc7, 0x13, 0xea, 0x33,
	0x4b, 0x31, 0xe8, 0x43, 0x68, 0xe6, 0x9c, 0x8b, 0xd8, 0xd2, 0x87, 0xc6, 0xfb, 0x32, 0xb6, 0x9e,
	0xf3, 0x35, 0xaf, 0x75, 0xa0, 0x2e, 0x1e, 0x01, 0xce, 0x54, 0x2b, 0xc6, 0x47, 0xa5, 0xb5, 0x93,
	0xc2, 0x67, 0xb2, 0x03, 0x19, 0x11, 0x66, 0xab, 0x88, 0x8f, 0xcb, 0x88, 0x30, 0x2b, 0x23, 0x0e,
	0x3f, 0x85, 0x47, 0xe5, 0x1b, 0x8e, 0x5a, 0x50, 0xeb, 0xdb, 0x1e, 0xb9, 0xb0, 0x2e, 0xc9, 0x0b,
	0xf3, 0x0b, 0xfd, 0xdb, 0x75, 0xc0, 0x3c, 0x39, 0xd5, 0xbf, 0x3b, 0xfc, 0x43, 0x83, 0xe6, 0xa6,
	0xb9, 0xd0, 0x63, 0x68, 0x08, 0xc4, 0x71, 0x89, 0xf5, 0x55, 0xdf, 0xb9, 0xb0, 0xf5, 0x07, 0x68,
	0x0f, 0x74, 0x01, 0x79, 0xb6, 0xe7, 0x0d, 0x5c, 0x87, 0x0c, 0x9c, 0x81, 0xaf, 0x6b, 0xe8, 0x1d,
	0x78, 0xba, 0x8e, 0x5a, 0xee, 0x6b, 0x1b, 0xfb, 0x8a, 0xac, 0x21, 0x03, 0xf6, 0x04, 0x69, 0x7f,
	0x33, 0xb2, 0x2d, 0x9f, 0x60, 0xdb, 0x72, 0x1d, 0xc7, 0xb6, 0x7c, 0x7d, 0x0b, 0xb5, 0xe1, 0xf1,
	0x46, 0xda, 0xd0, 0xf5, 0x6c, 0xbd, 0xb2, 0xa8, 0x71, 0x3d, 0xb0, 0x87, 0xe7, 0xe4, 0x6a, 0x34,
	0x74, 0xfb, 0xe7, 0xfa, 0x36, 0xda, 0x07, 0x24, 0xd0, 0xbe, 0xf5, 0xf5, 0xd5, 0x00, 0xdb, 0x0b,
	0xfc, 0x21, 0xea, 0xc0, 0xbb, 0x6b, 0xd7, 0x2b, 0xd8, 0x75, 0x86, 0xd7, 0x65, 0x25, 0x7d, 0x07,
	0x35, 0xa1, 0x2a, 0x23, 0x30, 0x76, 0xb1, 0xfe, 0xa7, 0x76, 0xf8, 0xa3, 0x06, 0xcd, 0xcd, 0x87,
	0x4c, 0x28, 0x15, 0xc8, 0x3d, 0xa5, 0x02, 0x7a, 0x53, 0xe9, 0x3a, 0xba, 0xa9, 0xf4, 0x2d, 0x68,
	0x0b, 0xd2, 0x72, 0x9d, 0x2f, 0x07, 0xf8, 0xf2, 0xbe, 0xd4, 0x8d, 0xbc, 0x52, 0x6a, 0x13, 0xaa,
	0x02, 0x5e, 0xb6, 0xf6, 0xb3, 0x06, 0xcd, 0xcd, 0xd7, 0x0e, 0xd5, 0x61, 0xd7, 0x71, 0xcb, 0x88,
	0x07, 0x72, 0x25, 0xaa, 0xa6, 0xe7, 0x63, 0xbb, 0x7f, 0xa9, 0x6b, 0xe8, 0x09, 0xb4, 0xac, 0xe1,
	0xc0, 0x76, 0xc4, 0x6c, 0x47, 0x2e, 0xf6, 0xed, 0x73, 0x7d, 0x6b, 0x0d, 0x1c, 0x61, 0xd7, 0x77,
	0x2d, 0x77, 0xa8, 0x06, 0xeb, 0xf9, 0x7d, 0x5f, 0xc9, 0xf1, 0x6d, 0xec, 0xf4, 0x87, 0xfa, 0x36,
	0x42, 0xd0, 0x3c, 0xb7, 0x2d, 0xf7, 0x9a, 0x88, 0x7b, 0xcb, 0xa1, 0x8a, 0x32, 0x2a, 0xbd, 0x2c,
	0x13, 0x89, 0xb0, 0x12, 0xf2, 0x07, 0x97, 0xb6, 0x7b, 0xe5, 0xeb, 0xf4, 0xaf, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x1b, 0x1f, 0x8e, 0xba, 0x73, 0x08, 0x00, 0x00,
}
