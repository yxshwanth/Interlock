//go:build !linux

package bridge

import (
	"fmt"
	"net"
)

func peerCreds(conn net.Conn) (uid, gid uint32, err error) {
	return 0, 0, fmt.Errorf("peercred: only supported on linux")
}

func chownSocket(path string, gid int) error {
	return nil
}
