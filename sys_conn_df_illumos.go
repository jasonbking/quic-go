//go:build illumos

package quic

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go/internal/utils"
)

func setDF(rawConn syscall.RawConn) (bool, error) {
	// IP_DONTFRAG / IPV6_DONTFRAG instruct the kernel to set the IPv4 DF
	// bit / suppress IPv6 fragmentation, and to fail sends with EMSGSIZE
	// instead of fragmenting, which is what we want for DPLPMTUD.
	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	}); err != nil {
		return false, err
	}
	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		utils.DefaultLogger.Debugf("Setting DF for IPv6.")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		return false, errors.New("setting DF failed for both IPv4 and IPv6")
	}
	return true, nil
}

func isSendMsgSizeErr(err error) bool {
	return errors.Is(err, unix.EMSGSIZE)
}

func isRecvMsgSizeErr(error) bool { return false }
