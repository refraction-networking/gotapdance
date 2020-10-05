package getifaddr

/*
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

char ADDR[INET6_ADDRSTRLEN];
*/
import "C"
import (
	"unsafe"
	"net"
)

// Get all interfaces on the device and check if they support by identifying 
//  a non-local interface with an assigned ipv6 address
func SupportsIpv6() (bool) {
	var ifaces *C.struct_ifaddrs

	if getrc, _ := C.getifaddrs(&ifaces); getrc != 0 {
		return false
	}
	defer C.freeifaddrs(ifaces)

	for fi := ifaces; fi != nil; fi = fi.ifa_next {

		if fi.ifa_addr == nil || fi.ifa_addr.sa_family != C.AF_INET6 {
			continue
		}

		sa_in := (*C.struct_sockaddr_in6)(unsafe.Pointer(fi.ifa_addr))
		if C.inet_ntop(
			C.int(fi.ifa_addr.sa_family), 
			unsafe.Pointer(&sa_in.sin6_addr),
			&C.ADDR[0],
			C.socklen_t(unsafe.Sizeof(C.ADDR))) != nil {

			IpStr := C.GoString((*C.char)(unsafe.Pointer(&C.ADDR[0])))
			if realInterfaceAddr( IpStr ) {
				return true
			}
		} else {
			continue
		}
		
	}
	return false
}

var netBlacklistv6 = map[string]string{
	"multicast": "ff00::/8",
	"private":   "fc00::/7",
	"link":	  	 "fe80::/10",
	"lo":		 "::1/128",
}

func realInterfaceAddr(IPStr string) bool {
	addr := net.ParseIP( IPStr )
	if addr == nil {
		return false
	}

	for _, netStr := range netBlacklistv6{
		_, blacklistNet, err := net.ParseCIDR(netStr)
		if err != nil {
			return false
		}
		if blacklistNet.Contains(addr) {
			return false
		}
	}
	return true
}

