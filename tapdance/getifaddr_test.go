package tapdance

import (
	"fmt"
	"testing"
)

func TestIpV6Support(t *testing.T) {
	fmt.Println("Testing IPv6 Support")

	fmt.Printf("Supports IPV6: %t\n", SupportsIpv6())
	// fmt.Printf("Supports IPV4: %t\n", SupportsIpv4())
}
