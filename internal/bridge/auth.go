package bridge

import "os"

// AuthPolicy restricts which Unix peers may talk to the taint bridge via SO_PEERCRED.
// When Active(), at least one of AllowedUIDs / AllowedGIDs is non-empty and the
// peer must match (UID ∈ list if UIDs set; GID ∈ list if GIDs set).
type AuthPolicy struct {
	AllowedUIDs []int
	AllowedGIDs []int
	SocketGID   int  // if > 0, chown socket to this GID after bind
	DirGroupOK  bool // if true, mkdir/chmod dir 0750 instead of 0700 for group share
}

// Active reports whether peercred enforcement is enabled.
func (p AuthPolicy) Active() bool {
	return len(p.AllowedUIDs) > 0 || len(p.AllowedGIDs) > 0
}

// Allow reports whether uid/gid are permitted.
func (p AuthPolicy) Allow(uid, gid uint32) bool {
	if !p.Active() {
		return true
	}
	uidOK := len(p.AllowedUIDs) == 0
	for _, u := range p.AllowedUIDs {
		if u >= 0 && uint32(u) == uid {
			uidOK = true
			break
		}
	}
	gidOK := len(p.AllowedGIDs) == 0
	for _, g := range p.AllowedGIDs {
		if g >= 0 && uint32(g) == gid {
			gidOK = true
			break
		}
	}
	return uidOK && gidOK
}

// SelfUIDAuth returns a policy that only allows the current process euid.
// Useful for same-binary tests and single-user local runs.
func SelfUIDAuth() AuthPolicy {
	return AuthPolicy{AllowedUIDs: []int{os.Geteuid()}}
}
