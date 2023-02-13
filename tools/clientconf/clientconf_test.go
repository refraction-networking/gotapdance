package main

import (
	"reflect"
	"testing"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestUpdateDNSReg(t *testing.T) {
	originalTarget := "original target"
	originalDomain := "original domain"
	originalMethod := pb.DnsRegMethod_UDP
	originalPubkey := []byte{1, 2}
	original := &pb.DnsRegConf{
		DnsRegMethod: &originalMethod,
		Target:       &originalTarget,
		Domain:       &originalDomain,
		Pubkey:       originalPubkey,
	}

	newTarget := "target"
	newMethod := pb.DnsRegMethod_DOH
	newPubkey := []byte{3, 4}
	new := &pb.DnsRegConf{
		Target:       &newTarget,
		DnsRegMethod: &newMethod,
		Pubkey:       newPubkey,
	}

	err := updateDNSReg(original, new)
	if err != nil {
		t.Fatalf("error during update reg: %v", err)
	}

	if *original.Domain != originalDomain {
		t.Fatalf("domain should not be updated")
	}

	if *original.Target == originalTarget {
		t.Fatalf("failed to update target")
	}

	if *original.DnsRegMethod == originalMethod {
		t.Fatalf("failed to update method")
	}

	if reflect.DeepEqual(original.Pubkey, originalPubkey) {
		t.Fatalf("failed to update pubkey")
	}

}
