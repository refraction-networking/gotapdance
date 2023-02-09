// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.2
// source: clientconf.proto

package tdproto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RegistrarType int32

const (
	RegistrarType_REGISTRAR_TYPE_UNKNOWN RegistrarType = 0
	RegistrarType_REGISTRAR_TYPE_API     RegistrarType = 1
	RegistrarType_REGISTRAR_TYPE_DECOY   RegistrarType = 2
	RegistrarType_REGISTRAR_TYPE_DNS     RegistrarType = 3
)

// Enum value maps for RegistrarType.
var (
	RegistrarType_name = map[int32]string{
		0: "REGISTRAR_TYPE_UNKNOWN",
		1: "REGISTRAR_TYPE_API",
		2: "REGISTRAR_TYPE_DECOY",
		3: "REGISTRAR_TYPE_DNS",
	}
	RegistrarType_value = map[string]int32{
		"REGISTRAR_TYPE_UNKNOWN": 0,
		"REGISTRAR_TYPE_API":     1,
		"REGISTRAR_TYPE_DECOY":   2,
		"REGISTRAR_TYPE_DNS":     3,
	}
)

func (x RegistrarType) Enum() *RegistrarType {
	p := new(RegistrarType)
	*p = x
	return p
}

func (x RegistrarType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RegistrarType) Descriptor() protoreflect.EnumDescriptor {
	return file_clientconf_proto_enumTypes[0].Descriptor()
}

func (RegistrarType) Type() protoreflect.EnumType {
	return &file_clientconf_proto_enumTypes[0]
}

func (x RegistrarType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *RegistrarType) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = RegistrarType(num)
	return nil
}

// Deprecated: Use RegistrarType.Descriptor instead.
func (RegistrarType) EnumDescriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{0}
}

type RegistrarDNSProtocol int32

const (
	RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UNKNOWN RegistrarDNSProtocol = 0
	RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UDP     RegistrarDNSProtocol = 1
	RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_DOH     RegistrarDNSProtocol = 2
	RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_DOT     RegistrarDNSProtocol = 3
)

// Enum value maps for RegistrarDNSProtocol.
var (
	RegistrarDNSProtocol_name = map[int32]string{
		0: "REGISTRAR_DNS_PROTOCOL_UNKNOWN",
		1: "REGISTRAR_DNS_PROTOCOL_UDP",
		2: "REGISTRAR_DNS_PROTOCOL_DOH",
		3: "REGISTRAR_DNS_PROTOCOL_DOT",
	}
	RegistrarDNSProtocol_value = map[string]int32{
		"REGISTRAR_DNS_PROTOCOL_UNKNOWN": 0,
		"REGISTRAR_DNS_PROTOCOL_UDP":     1,
		"REGISTRAR_DNS_PROTOCOL_DOH":     2,
		"REGISTRAR_DNS_PROTOCOL_DOT":     3,
	}
)

func (x RegistrarDNSProtocol) Enum() *RegistrarDNSProtocol {
	p := new(RegistrarDNSProtocol)
	*p = x
	return p
}

func (x RegistrarDNSProtocol) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RegistrarDNSProtocol) Descriptor() protoreflect.EnumDescriptor {
	return file_clientconf_proto_enumTypes[1].Descriptor()
}

func (RegistrarDNSProtocol) Type() protoreflect.EnumType {
	return &file_clientconf_proto_enumTypes[1]
}

func (x RegistrarDNSProtocol) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Do not use.
func (x *RegistrarDNSProtocol) UnmarshalJSON(b []byte) error {
	num, err := protoimpl.X.UnmarshalJSONEnum(x.Descriptor(), b)
	if err != nil {
		return err
	}
	*x = RegistrarDNSProtocol(num)
	return nil
}

// Deprecated: Use RegistrarDNSProtocol.Descriptor instead.
func (RegistrarDNSProtocol) EnumDescriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{1}
}

// Represents an individual config
type DeploymentConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DecoyList          *DecoyList          `protobuf:"bytes,1,opt,name=decoy_list,json=decoyList" json:"decoy_list,omitempty"`
	Generation         *uint32             `protobuf:"varint,2,opt,name=generation" json:"generation,omitempty"`
	DefaultPubkey      *PubKey             `protobuf:"bytes,3,opt,name=default_pubkey,json=defaultPubkey" json:"default_pubkey,omitempty"`
	PhantomSubnetsList *PhantomSubnetsList `protobuf:"bytes,4,opt,name=phantom_subnets_list,json=phantomSubnetsList" json:"phantom_subnets_list,omitempty"`
	ConjurePubkey      *PubKey             `protobuf:"bytes,5,opt,name=conjure_pubkey,json=conjurePubkey" json:"conjure_pubkey,omitempty"`
	VersionNumber      *uint32             `protobuf:"varint,6,opt,name=version_number,json=versionNumber" json:"version_number,omitempty"`
	SuportedTransports []TransportType     `protobuf:"varint,7,rep,name=suported_transports,json=suportedTransports,enum=tapdance.TransportType" json:"suported_transports,omitempty"`
	Registrars         []*Registrar        `protobuf:"bytes,8,rep,name=registrars" json:"registrars,omitempty"`
}

func (x *DeploymentConfig) Reset() {
	*x = DeploymentConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_clientconf_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeploymentConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeploymentConfig) ProtoMessage() {}

func (x *DeploymentConfig) ProtoReflect() protoreflect.Message {
	mi := &file_clientconf_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeploymentConfig.ProtoReflect.Descriptor instead.
func (*DeploymentConfig) Descriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{0}
}

func (x *DeploymentConfig) GetDecoyList() *DecoyList {
	if x != nil {
		return x.DecoyList
	}
	return nil
}

func (x *DeploymentConfig) GetGeneration() uint32 {
	if x != nil && x.Generation != nil {
		return *x.Generation
	}
	return 0
}

func (x *DeploymentConfig) GetDefaultPubkey() *PubKey {
	if x != nil {
		return x.DefaultPubkey
	}
	return nil
}

func (x *DeploymentConfig) GetPhantomSubnetsList() *PhantomSubnetsList {
	if x != nil {
		return x.PhantomSubnetsList
	}
	return nil
}

func (x *DeploymentConfig) GetConjurePubkey() *PubKey {
	if x != nil {
		return x.ConjurePubkey
	}
	return nil
}

func (x *DeploymentConfig) GetVersionNumber() uint32 {
	if x != nil && x.VersionNumber != nil {
		return *x.VersionNumber
	}
	return 0
}

func (x *DeploymentConfig) GetSuportedTransports() []TransportType {
	if x != nil {
		return x.SuportedTransports
	}
	return nil
}

func (x *DeploymentConfig) GetRegistrars() []*Registrar {
	if x != nil {
		return x.Registrars
	}
	return nil
}

// Houses multiple deployment configs
type ClientConfig2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VersionNumber     *uint32             `protobuf:"varint,1,opt,name=version_number,json=versionNumber" json:"version_number,omitempty"`
	DeploymentConfigs []*DeploymentConfig `protobuf:"bytes,2,rep,name=deployment_configs,json=deploymentConfigs" json:"deployment_configs,omitempty"`
}

func (x *ClientConfig2) Reset() {
	*x = ClientConfig2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_clientconf_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientConfig2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientConfig2) ProtoMessage() {}

func (x *ClientConfig2) ProtoReflect() protoreflect.Message {
	mi := &file_clientconf_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientConfig2.ProtoReflect.Descriptor instead.
func (*ClientConfig2) Descriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{1}
}

func (x *ClientConfig2) GetVersionNumber() uint32 {
	if x != nil && x.VersionNumber != nil {
		return *x.VersionNumber
	}
	return 0
}

func (x *ClientConfig2) GetDeploymentConfigs() []*DeploymentConfig {
	if x != nil {
		return x.DeploymentConfigs
	}
	return nil
}

type Registrar struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RegistrarType      *RegistrarType `protobuf:"varint,1,opt,name=registrar_type,json=registrarType,enum=tapdance.RegistrarType" json:"registrar_type,omitempty"`
	Bidirectional      *bool          `protobuf:"varint,2,opt,name=bidirectional" json:"bidirectional,omitempty"` // Expect response from registrar or not
	DnsRegConfParams   *DNSRegConf    `protobuf:"bytes,10,opt,name=dns_reg_conf_params,json=dnsRegConfParams" json:"dns_reg_conf_params,omitempty"`
	ApiRegConfParams   *APIRegConf    `protobuf:"bytes,20,opt,name=api_reg_conf_params,json=apiRegConfParams" json:"api_reg_conf_params,omitempty"`
	DecoyRegConfParams *DecoyRegConf  `protobuf:"bytes,30,opt,name=decoy_reg_conf_params,json=decoyRegConfParams" json:"decoy_reg_conf_params,omitempty"`
}

func (x *Registrar) Reset() {
	*x = Registrar{}
	if protoimpl.UnsafeEnabled {
		mi := &file_clientconf_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Registrar) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Registrar) ProtoMessage() {}

func (x *Registrar) ProtoReflect() protoreflect.Message {
	mi := &file_clientconf_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Registrar.ProtoReflect.Descriptor instead.
func (*Registrar) Descriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{2}
}

func (x *Registrar) GetRegistrarType() RegistrarType {
	if x != nil && x.RegistrarType != nil {
		return *x.RegistrarType
	}
	return RegistrarType_REGISTRAR_TYPE_UNKNOWN
}

func (x *Registrar) GetBidirectional() bool {
	if x != nil && x.Bidirectional != nil {
		return *x.Bidirectional
	}
	return false
}

func (x *Registrar) GetDnsRegConfParams() *DNSRegConf {
	if x != nil {
		return x.DnsRegConfParams
	}
	return nil
}

func (x *Registrar) GetApiRegConfParams() *APIRegConf {
	if x != nil {
		return x.ApiRegConfParams
	}
	return nil
}

func (x *Registrar) GetDecoyRegConfParams() *DecoyRegConf {
	if x != nil {
		return x.DecoyRegConfParams
	}
	return nil
}

type DNSRegConf struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DnsRegMethod     *RegistrarDNSProtocol `protobuf:"varint,1,req,name=dns_reg_method,json=dnsRegMethod,enum=tapdance.RegistrarDNSProtocol" json:"dns_reg_method,omitempty"`
	UdpAddr          *string               `protobuf:"bytes,2,opt,name=udp_addr,json=udpAddr" json:"udp_addr,omitempty"`
	DotAddr          *string               `protobuf:"bytes,3,opt,name=dot_addr,json=dotAddr" json:"dot_addr,omitempty"`
	DohUrl           *string               `protobuf:"bytes,4,opt,name=doh_url,json=dohUrl" json:"doh_url,omitempty"`
	Domain           *string               `protobuf:"bytes,5,req,name=domain" json:"domain,omitempty"`
	Pubkey           []byte                `protobuf:"bytes,6,req,name=pubkey" json:"pubkey,omitempty"`
	UtlsDistribution *string               `protobuf:"bytes,7,opt,name=utls_distribution,json=utlsDistribution" json:"utls_distribution,omitempty"`
	StunServer       *string               `protobuf:"bytes,8,opt,name=stun_server,json=stunServer" json:"stun_server,omitempty"`
}

func (x *DNSRegConf) Reset() {
	*x = DNSRegConf{}
	if protoimpl.UnsafeEnabled {
		mi := &file_clientconf_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DNSRegConf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DNSRegConf) ProtoMessage() {}

func (x *DNSRegConf) ProtoReflect() protoreflect.Message {
	mi := &file_clientconf_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DNSRegConf.ProtoReflect.Descriptor instead.
func (*DNSRegConf) Descriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{3}
}

func (x *DNSRegConf) GetDnsRegMethod() RegistrarDNSProtocol {
	if x != nil && x.DnsRegMethod != nil {
		return *x.DnsRegMethod
	}
	return RegistrarDNSProtocol_REGISTRAR_DNS_PROTOCOL_UNKNOWN
}

func (x *DNSRegConf) GetUdpAddr() string {
	if x != nil && x.UdpAddr != nil {
		return *x.UdpAddr
	}
	return ""
}

func (x *DNSRegConf) GetDotAddr() string {
	if x != nil && x.DotAddr != nil {
		return *x.DotAddr
	}
	return ""
}

func (x *DNSRegConf) GetDohUrl() string {
	if x != nil && x.DohUrl != nil {
		return *x.DohUrl
	}
	return ""
}

func (x *DNSRegConf) GetDomain() string {
	if x != nil && x.Domain != nil {
		return *x.Domain
	}
	return ""
}

func (x *DNSRegConf) GetPubkey() []byte {
	if x != nil {
		return x.Pubkey
	}
	return nil
}

func (x *DNSRegConf) GetUtlsDistribution() string {
	if x != nil && x.UtlsDistribution != nil {
		return *x.UtlsDistribution
	}
	return ""
}

func (x *DNSRegConf) GetStunServer() string {
	if x != nil && x.StunServer != nil {
		return *x.StunServer
	}
	return ""
}

type APIRegConf struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ApiUrl *string `protobuf:"bytes,1,opt,name=api_url,json=apiUrl" json:"api_url,omitempty"`
}

func (x *APIRegConf) Reset() {
	*x = APIRegConf{}
	if protoimpl.UnsafeEnabled {
		mi := &file_clientconf_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *APIRegConf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*APIRegConf) ProtoMessage() {}

func (x *APIRegConf) ProtoReflect() protoreflect.Message {
	mi := &file_clientconf_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use APIRegConf.ProtoReflect.Descriptor instead.
func (*APIRegConf) Descriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{4}
}

func (x *APIRegConf) GetApiUrl() string {
	if x != nil && x.ApiUrl != nil {
		return *x.ApiUrl
	}
	return ""
}

type DecoyRegConf struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DecoyRegConf) Reset() {
	*x = DecoyRegConf{}
	if protoimpl.UnsafeEnabled {
		mi := &file_clientconf_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DecoyRegConf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecoyRegConf) ProtoMessage() {}

func (x *DecoyRegConf) ProtoReflect() protoreflect.Message {
	mi := &file_clientconf_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DecoyRegConf.ProtoReflect.Descriptor instead.
func (*DecoyRegConf) Descriptor() ([]byte, []int) {
	return file_clientconf_proto_rawDescGZIP(), []int{5}
}

var File_clientconf_proto protoreflect.FileDescriptor

var file_clientconf_proto_rawDesc = []byte{
	0x0a, 0x10, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x63, 0x6f, 0x6e, 0x66, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x08, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x1a, 0x10, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xce,
	0x03, 0x0a, 0x10, 0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x12, 0x32, 0x0a, 0x0a, 0x64, 0x65, 0x63, 0x6f, 0x79, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e,
	0x63, 0x65, 0x2e, 0x44, 0x65, 0x63, 0x6f, 0x79, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x09, 0x64, 0x65,
	0x63, 0x6f, 0x79, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x67, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x67, 0x65, 0x6e,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x37, 0x0a, 0x0e, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x5f, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x10, 0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x50, 0x75, 0x62, 0x4b, 0x65,
	0x79, 0x52, 0x0d, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79,
	0x12, 0x4e, 0x0a, 0x14, 0x70, 0x68, 0x61, 0x6e, 0x74, 0x6f, 0x6d, 0x5f, 0x73, 0x75, 0x62, 0x6e,
	0x65, 0x74, 0x73, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c,
	0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x50, 0x68, 0x61, 0x6e, 0x74, 0x6f,
	0x6d, 0x53, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x12, 0x70, 0x68,
	0x61, 0x6e, 0x74, 0x6f, 0x6d, 0x53, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x73, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x37, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x6a, 0x75, 0x72, 0x65, 0x5f, 0x70, 0x75, 0x62, 0x6b,
	0x65, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x74, 0x61, 0x70, 0x64, 0x61,
	0x6e, 0x63, 0x65, 0x2e, 0x50, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x52, 0x0d, 0x63, 0x6f, 0x6e, 0x6a,
	0x75, 0x72, 0x65, 0x50, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x12, 0x25, 0x0a, 0x0e, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0d, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
	0x12, 0x48, 0x0a, 0x13, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x17, 0x2e,
	0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x54, 0x79, 0x70, 0x65, 0x52, 0x12, 0x73, 0x75, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64,
	0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x12, 0x33, 0x0a, 0x0a, 0x72, 0x65,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13,
	0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74,
	0x72, 0x61, 0x72, 0x52, 0x0a, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72, 0x73, 0x22,
	0x81, 0x01, 0x0a, 0x0d, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x32, 0x12, 0x25, 0x0a, 0x0e, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x49, 0x0a, 0x12, 0x64, 0x65, 0x70, 0x6c,
	0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x18, 0x02,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e,
	0x44, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x52, 0x11, 0x64, 0x65, 0x70, 0x6c, 0x6f, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x73, 0x22, 0xc6, 0x02, 0x0a, 0x09, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61,
	0x72, 0x12, 0x3e, 0x0a, 0x0e, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x74, 0x61, 0x70, 0x64,
	0x61, 0x6e, 0x63, 0x65, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x0d, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x24, 0x0a, 0x0d, 0x62, 0x69, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x61, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x62, 0x69, 0x64, 0x69, 0x72, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x12, 0x43, 0x0a, 0x13, 0x64, 0x6e, 0x73, 0x5f, 0x72,
	0x65, 0x67, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e,
	0x44, 0x4e, 0x53, 0x52, 0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x52, 0x10, 0x64, 0x6e, 0x73, 0x52,
	0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x43, 0x0a, 0x13,
	0x61, 0x70, 0x69, 0x5f, 0x72, 0x65, 0x67, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x5f, 0x70, 0x61, 0x72,
	0x61, 0x6d, 0x73, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x74, 0x61, 0x70, 0x64,
	0x61, 0x6e, 0x63, 0x65, 0x2e, 0x41, 0x50, 0x49, 0x52, 0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x52,
	0x10, 0x61, 0x70, 0x69, 0x52, 0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x50, 0x61, 0x72, 0x61, 0x6d,
	0x73, 0x12, 0x49, 0x0a, 0x15, 0x64, 0x65, 0x63, 0x6f, 0x79, 0x5f, 0x72, 0x65, 0x67, 0x5f, 0x63,
	0x6f, 0x6e, 0x66, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x16, 0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x44, 0x65, 0x63, 0x6f,
	0x79, 0x52, 0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x52, 0x12, 0x64, 0x65, 0x63, 0x6f, 0x79, 0x52,
	0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x22, 0x9f, 0x02, 0x0a,
	0x0a, 0x44, 0x4e, 0x53, 0x52, 0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x12, 0x44, 0x0a, 0x0e, 0x64,
	0x6e, 0x73, 0x5f, 0x72, 0x65, 0x67, 0x5f, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x01, 0x20,
	0x02, 0x28, 0x0e, 0x32, 0x1e, 0x2e, 0x74, 0x61, 0x70, 0x64, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x52,
	0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72, 0x44, 0x4e, 0x53, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x63, 0x6f, 0x6c, 0x52, 0x0c, 0x64, 0x6e, 0x73, 0x52, 0x65, 0x67, 0x4d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x12, 0x19, 0x0a, 0x08, 0x75, 0x64, 0x70, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x75, 0x64, 0x70, 0x41, 0x64, 0x64, 0x72, 0x12, 0x19, 0x0a, 0x08,
	0x64, 0x6f, 0x74, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x64, 0x6f, 0x74, 0x41, 0x64, 0x64, 0x72, 0x12, 0x17, 0x0a, 0x07, 0x64, 0x6f, 0x68, 0x5f, 0x75,
	0x72, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x68, 0x55, 0x72, 0x6c,
	0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x05, 0x20, 0x02, 0x28, 0x09,
	0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x75, 0x62, 0x6b,
	0x65, 0x79, 0x18, 0x06, 0x20, 0x02, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79,
	0x12, 0x2b, 0x0a, 0x11, 0x75, 0x74, 0x6c, 0x73, 0x5f, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62,
	0x75, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x75, 0x74, 0x6c,
	0x73, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1f, 0x0a,
	0x0b, 0x73, 0x74, 0x75, 0x6e, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x73, 0x74, 0x75, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x22, 0x25,
	0x0a, 0x0a, 0x41, 0x50, 0x49, 0x52, 0x65, 0x67, 0x43, 0x6f, 0x6e, 0x66, 0x12, 0x17, 0x0a, 0x07,
	0x61, 0x70, 0x69, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x61,
	0x70, 0x69, 0x55, 0x72, 0x6c, 0x22, 0x0e, 0x0a, 0x0c, 0x44, 0x65, 0x63, 0x6f, 0x79, 0x52, 0x65,
	0x67, 0x43, 0x6f, 0x6e, 0x66, 0x2a, 0x75, 0x0a, 0x0d, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72,
	0x61, 0x72, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x16, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54,
	0x52, 0x41, 0x52, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e,
	0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x52, 0x41, 0x52, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x41, 0x50, 0x49, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x52, 0x45,
	0x47, 0x49, 0x53, 0x54, 0x52, 0x41, 0x52, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44, 0x45, 0x43,
	0x4f, 0x59, 0x10, 0x02, 0x12, 0x16, 0x0a, 0x12, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x52, 0x41,
	0x52, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44, 0x4e, 0x53, 0x10, 0x03, 0x2a, 0x9a, 0x01, 0x0a,
	0x14, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x72, 0x44, 0x4e, 0x53, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x22, 0x0a, 0x1e, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x52,
	0x41, 0x52, 0x5f, 0x44, 0x4e, 0x53, 0x5f, 0x50, 0x52, 0x4f, 0x54, 0x4f, 0x43, 0x4f, 0x4c, 0x5f,
	0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x1e, 0x0a, 0x1a, 0x52, 0x45, 0x47,
	0x49, 0x53, 0x54, 0x52, 0x41, 0x52, 0x5f, 0x44, 0x4e, 0x53, 0x5f, 0x50, 0x52, 0x4f, 0x54, 0x4f,
	0x43, 0x4f, 0x4c, 0x5f, 0x55, 0x44, 0x50, 0x10, 0x01, 0x12, 0x1e, 0x0a, 0x1a, 0x52, 0x45, 0x47,
	0x49, 0x53, 0x54, 0x52, 0x41, 0x52, 0x5f, 0x44, 0x4e, 0x53, 0x5f, 0x50, 0x52, 0x4f, 0x54, 0x4f,
	0x43, 0x4f, 0x4c, 0x5f, 0x44, 0x4f, 0x48, 0x10, 0x02, 0x12, 0x1e, 0x0a, 0x1a, 0x52, 0x45, 0x47,
	0x49, 0x53, 0x54, 0x52, 0x41, 0x52, 0x5f, 0x44, 0x4e, 0x53, 0x5f, 0x50, 0x52, 0x4f, 0x54, 0x4f,
	0x43, 0x4f, 0x4c, 0x5f, 0x44, 0x4f, 0x54, 0x10, 0x03, 0x42, 0x09, 0x5a, 0x07, 0x74, 0x64, 0x70,
	0x72, 0x6f, 0x74, 0x6f,
}

var (
	file_clientconf_proto_rawDescOnce sync.Once
	file_clientconf_proto_rawDescData = file_clientconf_proto_rawDesc
)

func file_clientconf_proto_rawDescGZIP() []byte {
	file_clientconf_proto_rawDescOnce.Do(func() {
		file_clientconf_proto_rawDescData = protoimpl.X.CompressGZIP(file_clientconf_proto_rawDescData)
	})
	return file_clientconf_proto_rawDescData
}

var file_clientconf_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_clientconf_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_clientconf_proto_goTypes = []interface{}{
	(RegistrarType)(0),         // 0: tapdance.RegistrarType
	(RegistrarDNSProtocol)(0),  // 1: tapdance.RegistrarDNSProtocol
	(*DeploymentConfig)(nil),   // 2: tapdance.DeploymentConfig
	(*ClientConfig2)(nil),      // 3: tapdance.ClientConfig2
	(*Registrar)(nil),          // 4: tapdance.Registrar
	(*DNSRegConf)(nil),         // 5: tapdance.DNSRegConf
	(*APIRegConf)(nil),         // 6: tapdance.APIRegConf
	(*DecoyRegConf)(nil),       // 7: tapdance.DecoyRegConf
	(*DecoyList)(nil),          // 8: tapdance.DecoyList
	(*PubKey)(nil),             // 9: tapdance.PubKey
	(*PhantomSubnetsList)(nil), // 10: tapdance.PhantomSubnetsList
	(TransportType)(0),         // 11: tapdance.TransportType
}
var file_clientconf_proto_depIdxs = []int32{
	8,  // 0: tapdance.DeploymentConfig.decoy_list:type_name -> tapdance.DecoyList
	9,  // 1: tapdance.DeploymentConfig.default_pubkey:type_name -> tapdance.PubKey
	10, // 2: tapdance.DeploymentConfig.phantom_subnets_list:type_name -> tapdance.PhantomSubnetsList
	9,  // 3: tapdance.DeploymentConfig.conjure_pubkey:type_name -> tapdance.PubKey
	11, // 4: tapdance.DeploymentConfig.suported_transports:type_name -> tapdance.TransportType
	4,  // 5: tapdance.DeploymentConfig.registrars:type_name -> tapdance.Registrar
	2,  // 6: tapdance.ClientConfig2.deployment_configs:type_name -> tapdance.DeploymentConfig
	0,  // 7: tapdance.Registrar.registrar_type:type_name -> tapdance.RegistrarType
	5,  // 8: tapdance.Registrar.dns_reg_conf_params:type_name -> tapdance.DNSRegConf
	6,  // 9: tapdance.Registrar.api_reg_conf_params:type_name -> tapdance.APIRegConf
	7,  // 10: tapdance.Registrar.decoy_reg_conf_params:type_name -> tapdance.DecoyRegConf
	1,  // 11: tapdance.DNSRegConf.dns_reg_method:type_name -> tapdance.RegistrarDNSProtocol
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_clientconf_proto_init() }
func file_clientconf_proto_init() {
	if File_clientconf_proto != nil {
		return
	}
	file_signalling_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_clientconf_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeploymentConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_clientconf_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientConfig2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_clientconf_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Registrar); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_clientconf_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DNSRegConf); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_clientconf_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*APIRegConf); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_clientconf_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DecoyRegConf); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_clientconf_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_clientconf_proto_goTypes,
		DependencyIndexes: file_clientconf_proto_depIdxs,
		EnumInfos:         file_clientconf_proto_enumTypes,
		MessageInfos:      file_clientconf_proto_msgTypes,
	}.Build()
	File_clientconf_proto = out.File
	file_clientconf_proto_rawDesc = nil
	file_clientconf_proto_goTypes = nil
	file_clientconf_proto_depIdxs = nil
}
