//go:build linux

package bridge

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerCreds(conn net.Conn) (uid, gid uint32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("peercred: not a unix conn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			cerr = e
			return
		}
		uid = cred.Uid
		gid = cred.Gid
	})
	if err != nil {
		return 0, 0, err
	}
	if cerr != nil {
		return 0, 0, cerr
	}
	return uid, gid, nil
}

func chownSocket(path string, gid int) error {
	if gid <= 0 {
		return nil
	}
	return unix.Chown(path, -1, gid)
}
