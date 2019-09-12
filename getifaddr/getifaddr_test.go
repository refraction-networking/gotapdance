package getifaddr

import (
	"fmt"
	"testing"
)

func TestIpV6Support(t *testing.T) {
	fmt.Printf("Supports IPV6: %t\n", SupportsIpv6())
}
