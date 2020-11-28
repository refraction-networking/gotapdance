package main

import (
	"net"
	"testing"
)

func TestCJProbeSelectFromSubnet(t *testing.T) {
	subnetStrings := []string{"10.0.0.1/8", "128.138.0.0/16"}
	var seed int64 = 1000

	strToNet := func(s []string) []*net.IPNet {
		list := []*net.IPNet{}
		for _, str := range s {
			_, subnet, err := net.ParseCIDR(str)
			if err != nil {
				t.Fatal(err)
			}
			list = append(list, subnet)
		}
		return list
	}

	selected := selectFromSubnets(strToNet(subnetStrings), 1, seed)
	if len(selected) != 2 {
		t.FailNow()
	} else if selected[0] != "10.138.86.216" || selected[1] != "128.138.31.3" {
		t.FailNow()
	}

	subnetStrings = []string{"fe80::/32"}
	selected = selectFromSubnets(strToNet(subnetStrings), 1, seed)
	if len(selected) != 1 {
		t.FailNow()
	} else if selected[0] != "fe80:0:b5fb:1f03:8ffb:fce7:9f18:5f4a" {
		t.FailNow()
	}

	subnetStrings = []string{"fe80::/32", "10.0.0.1/8"}
	selected = selectFromSubnets(strToNet(subnetStrings), 2, seed)
	if len(selected) != 4 {
		t.FailNow()
	} else if selected[0] != "fe80:0:b5fb:1f03:8ffb:fce7:9f18:5f4a" ||
		selected[1] != "fe80:0:94ed:b854:57d6:c84d:6bc0:2a82" ||
		selected[2] != "10.78.228.45" ||
		selected[3] != "10.30.156.59" {
		t.FailNow()
	}
}
