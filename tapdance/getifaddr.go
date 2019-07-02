package tapdance

/*
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

char ADDR[INET_ADDRSTRLEN];
*/
import "C"
import (
	"regexp"
	"runtime"
	"unsafe"
)

type InterfaceInfo struct {
	Name       string
	InBytes    uint
	OutBytes   uint
	InPackets  uint
	OutPackets uint
	InErrors   uint
	OutErrors  uint
}

type InterfacesInfo struct {
	List []InterfaceInfo
	IP   string
}


// Get all interfaces on the device and check if they support by identifying 
//  a non-local interface with an assigned ipv6 address
func SupportsIpv6() (bool) {
	var ifaces *C.struct_ifaddrs

	if getrc, _ := C.getifaddrs(&ifaces); getrc != 0 {
		return false
	}
	defer C.freeifaddrs(ifaces)

	for fi := ifaces; fi != nil; fi = fi.ifa_next {

		ifa_name := C.GoString(fi.ifa_name)
		// ifa_family := C.int(fi.ifa_addr.sa_family)

		if fi.ifa_addr == nil  || 
			fi.ifa_addr.sa_family != C.AF_INET6 ||
			rx_lo.Match([]byte(ifa_name)) || 
			!realInterfaceName(ifa_name) {
			continue
		}

		sa_in := (*C.struct_sockaddr_in)(unsafe.Pointer(fi.ifa_addr))
		if C.inet_ntop(
			C.int(fi.ifa_addr.sa_family), 
			unsafe.Pointer(&sa_in.sin_addr),
			&C.ADDR[0],
			C.socklen_t(unsafe.Sizeof(C.ADDR))) != nil {

			// IP := C.GoString((*C.char)(unsafe.Pointer(&C.ADDR)))
			return true
		} else {
			continue
		}
		
	}
	return false
}

/*
func SupportsIpv4() (bool) {
	var ifaces *C.struct_ifaddrs

	if getrc, _ := C.getifaddrs(&ifaces); getrc != 0 {
		return false
	}
	defer C.freeifaddrs(ifaces)

	for fi := ifaces; fi != nil; fi = fi.ifa_next {

		ifa_name := C.GoString(fi.ifa_name)
		// ifa_family := C.int(fi.ifa_addr.sa_family)

		if fi.ifa_addr == nil  || 
			fi.ifa_addr.sa_family != C.AF_INET ||
			rx_lo.Match([]byte(ifa_name)) || 
			!realInterfaceName(ifa_name) {
			continue
		}

		sa_in := (*C.struct_sockaddr_in)(unsafe.Pointer(fi.ifa_addr))
		if C.inet_ntop(
			C.int(fi.ifa_addr.sa_family), 
			unsafe.Pointer(&sa_in.sin_addr),
			&C.ADDR[0],
			C.socklen_t(unsafe.Sizeof(C.ADDR))) != nil {

			// IP := C.GoString((*C.char)(unsafe.Pointer(&C.ADDR)))
			return true
		} else {
			continue
		}
		
	}
	return false
}*/

var (
	rx_lo      = regexp.MustCompile("lo\\d*") // "lo" & lo\d+; used in interfaces_unix.go, sortable.go
	RX_fw      = regexp.MustCompile("fw\\d+")
	RX_gif     = regexp.MustCompile("gif\\d+")
	RX_stf     = regexp.MustCompile("stf\\d+")
	RX_bridge  = regexp.MustCompile("bridge\\d+")
	RX_vboxnet = regexp.MustCompile("vboxnet\\d+")
	RX_airdrop = regexp.MustCompile("p2p\\d+")
)

func realInterfaceName(name string) bool {
	bname := []byte(name)
	if RX_bridge.Match(bname) ||
		RX_vboxnet.Match(bname) {
		return false
	}
	is_darwin := runtime.GOOS == "darwin"
	if is_darwin {
		if RX_fw.Match(bname) ||
			RX_gif.Match(bname) ||
			RX_stf.Match(bname) ||
			RX_airdrop.Match(bname) {
			return false
		}
	}
	return true
}

func filterInterfaces(ifs []InterfaceInfo) []InterfaceInfo {
	fifs := []InterfaceInfo{}
	for _, fi := range ifs {
		if !realInterfaceName(fi.Name) {
			continue
		}
		fifs = append(fifs, fi)
	}
	return fifs
}
