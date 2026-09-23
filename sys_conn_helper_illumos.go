//go:build illumos

package quic

import (
	"encoding/binary"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	msgTypeIPTOS = unix.IP_RECVTOS
	ipv4PKTINFO  = unix.IP_RECVPKTINFO
)

const ecnIPv4DataLen = 1

const batchSize = 8

func parseIPv4PktInfo(body []byte) (ip netip.Addr, ifIndex uint32, ok bool) {
	// struct in_pktinfo {
	// 	unsigned int   ipi_ifindex;   /* send/recv interface index */
	// 	struct in_addr ipi_spec_dst;  /* matched source address */
	// 	struct in_addr ipi_addr;      /* src/dst address in IP hdr */
	// };
	if len(body) != 12 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4(*(*[4]byte)(body[8:12])), binary.NativeEndian.Uint32(body), true
}

func isGSOEnabled(syscall.RawConn) bool { return false }

func isECNEnabled() bool { return !isECNDisabledUsingEnv() }
