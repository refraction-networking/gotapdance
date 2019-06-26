package tapdance

/*
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#ifndef AF_LINK
#define AF_LINK AF_PACKET
#endif

#ifndef __linux__ // NOT LINUX
u_int32_t Ibytes(void *data) { return ((struct if_data *)data)->ifi_ibytes; }
u_int32_t Obytes(void *data) { return ((struct if_data *)data)->ifi_obytes; }

u_int32_t Ipackets(void *data) { return ((struct if_data *)data)->ifi_ipackets; }
u_int32_t Opackets(void *data) { return ((struct if_data *)data)->ifi_opackets; }

u_int32_t Ierrors(void *data) { return ((struct if_data *)data)->ifi_ierrors; }
u_int32_t Oerrors(void *data) { return ((struct if_data *)data)->ifi_oerrors; }

#else
#include <linux/if_link.h>
u_int32_t Ibytes(void *data) { return ((struct rtnl_link_stats *)data)->rx_bytes; }
u_int32_t Obytes(void *data) { return ((struct rtnl_link_stats *)data)->tx_bytes; }

u_int32_t Ipackets(void *data) { return ((struct rtnl_link_stats *)data)->rx_packets; }
u_int32_t Opackets(void *data) { return ((struct rtnl_link_stats *)data)->tx_packets; }

u_int32_t Ierrors(void *data) { return ((struct rtnl_link_stats *)data)->rx_errors; }
u_int32_t Oerrors(void *data) { return ((struct rtnl_link_stats *)data)->tx_errors; }
#endif

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

func NewInterfaces(CH chan InterfacesInfo) {
	var ifaces *C.struct_ifaddrs
	if getrc, _ := C.getifaddrs(&ifaces); getrc != 0 {
		CH <- InterfacesInfo{}
		return
	}
	defer C.freeifaddrs(ifaces)

	ifs := []InterfaceInfo{}
	IP := ""

	for fi := ifaces; fi != nil; fi = fi.ifa_next {
		if fi.ifa_addr == nil {
			continue
		}

		ifa_name := C.GoString(fi.ifa_name)
		if IP == "" &&
			fi.ifa_addr.sa_family == C.AF_INET &&
			!rx_lo.Match([]byte(ifa_name)) &&
			realInterfaceName(ifa_name) {

			sa_in := (*C.struct_sockaddr_in)(unsafe.Pointer(fi.ifa_addr))
			if C.inet_ntop(
				C.int(fi.ifa_addr.sa_family), // C.AF_INET,
				unsafe.Pointer(&sa_in.sin_addr),
				&C.ADDR[0],
				C.socklen_t(unsafe.Sizeof(C.ADDR))) != nil {

				IP = C.GoString((*C.char)(unsafe.Pointer(&C.ADDR)))
			}
		}

		if fi.ifa_addr.sa_family != C.AF_LINK {
			continue
		}

		data := fi.ifa_data
		it := InterfaceInfo{
			Name:       ifa_name,
			InBytes:    uint(C.Ibytes(data)),
			OutBytes:   uint(C.Obytes(data)),
			InPackets:  uint(C.Ipackets(data)),
			OutPackets: uint(C.Opackets(data)),
			InErrors:   uint(C.Ierrors(data)),
			OutErrors:  uint(C.Oerrors(data)),
		}
		if it.InBytes == 0 &&
			it.OutBytes == 0 &&
			it.InPackets == 0 &&
			it.OutPackets == 0 &&
			it.InErrors == 0 &&
			it.OutErrors == 0 {
			continue
		}
		ifs = append(ifs, it)
	}
	CH <- InterfacesInfo{
		List: ifs,
		IP:   IP,
	}
}

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

/*
func netinterface_ipaddr() (string, error) {
	// list of the system's network interfaces.
	list_iface, err := net.Interfaces()
	// var ifaces ost_api.Interfaces
	if err != nil {
		return "", err
	}
	var addr []string
	for _, iface := range list_iface {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !realInterfaceName(iface.Name) {
			continue
		}
		if aa, err := iface.Addrs(); err == nil {
			if len(aa) == 0 {
				continue
			}
			for _, a := range aa {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					return "", fmt.Errorf("Not an IP: %v", a)
					continue
				}
				if ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				addr = append(addr, ipnet.IP.String())
			}
		}
	}
	if len(addr) == 0 {
		return "", nil
	}
	return addr[0], nil
} // */

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
