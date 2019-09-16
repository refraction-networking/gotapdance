package getifaddr

import (
	"fmt"
	"testing"
)

func DisabledTestIpV6Support(t *testing.T) {
	fmt.Printf("Supports IPV6: %t\n", SupportsIpv6())
}

func TestInterfaceExclusion(t *testing.T) {
	var badAddrs = []string{
		"ff00::1:22:8",
		"fcff::22:1234",
		"fe80::a684:828:3aea:c02",
		"fdd0:d118:70ed:0:a17e:ba2:ac97:b72d",
		"fe80::ebdd:eef3:fc1a:ffb",
	}
	var goodAddrs = []string{
		"11:22:33:44::1",
		"abcd::ef01",
		"2a03:2880:f11c:8083:face:b00c:0:25de",
		"2a03:2880:f11b:83:face:b00c:0:25",
	}

	for _, addr := range badAddrs {
		if realInterfaceAddr(addr) {
			t.Fatalf("Bad address not filtered: %s", addr)
		}
	}
	for _, addr := range goodAddrs {
		if !realInterfaceAddr(addr) {
			t.Fatalf("Good address wrongly filtered: %s", addr)
		}
	}
}
