package tdproto

import (
  "github.com/golang/protobuf/proto"
  // pb "github.com/refraction-networking/gotapdance/protobuf"
  "fmt"
  "testing"
)

// Write a small go test using your APIMessage (serialize/deserialize)
func TestBidirectionalAPIResponse(t *testing.T) {
  c2s := RegistrationResponse{}
  addr := uint32(12345)
  c2s.Ipv4Addr = &addr
  port := uint32(10)
  c2s.Port = &port

  // Serialize
  marsh, err := proto.Marshal(&c2s)
  if err != nil {
    t.Fatalf("Failed to serialize registration response: expected nil, got %v", err)
  }

  // Deserialize
  deser := RegistrationResponse{}
  if err := proto.Unmarshal(marsh, &deser); err != nil {
    t.Fatalf("Bad registration response returned")
  }

  // Test for correctness
  correctIpv4 := uint32(12345)
  correctPort := uint32(10)

  if *deser.Ipv4Addr != correctIpv4 {
    t.Fatalf("Registration response has wrong ipv4address")
  }

  if *deser.Port != correctPort {
    t.Fatalf("Registration response has wrong port")
  }

  // Success if doesn't fail above
  fmt.Println("")
  fmt.Println("Success!")

}
