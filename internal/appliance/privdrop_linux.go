//go:build linux

package appliance

import (
	"fmt"
	"os"
	"syscall"
)

// Privilege drop, replacing `gosu idp:idp`.
//
// WHY THIS IS SAFE IN GO NOW. The historical objection is real: setuid(2)
// affects only the calling thread, and a Go program has many. Since Go 1.16
// syscall.Setuid/Setgid on Linux are implemented with a signal-broadcast that
// applies the change to EVERY thread, which is exactly what gosu did by
// dropping before exec. Without that, this would leave privileged threads
// behind and be worse than the shell it replaces.
//
// ORDER MATTERS AND IS NOT INTERCHANGEABLE: groups, then gid, then uid. Once
// the uid is dropped the process can no longer change its groups, so a
// setuid-first sequence silently keeps root's supplementary groups — a classic
// privilege-drop bug that leaves the process more privileged than intended.

// IsRoot reports whether this process is running as uid 0.
func IsRoot() bool { return os.Geteuid() == 0 }

// Chown is the real chown, injected into Prepare so the flow stays testable.
func Chown(path string, uid, gid int) error { return os.Chown(path, uid, gid) }

// DropPrivileges permanently drops to uid/gid. A no-op when not root, so the
// common case — a container already running as the unprivileged user — costs
// nothing and takes the same code path.
func DropPrivileges(uid, gid int) error {
	if !IsRoot() {
		return nil
	}
	if uid == 0 || gid == 0 {
		return fmt.Errorf("appliance: refusing to \"drop\" privileges to uid=%d gid=%d — "+
			"that is not a drop", uid, gid)
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("appliance: setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("appliance: setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("appliance: setuid(%d): %w", uid, err)
	}
	// VERIFY, do not assume. A drop that silently did not happen is the worst
	// outcome here: the process would serve as root believing it had dropped.
	if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("appliance: privilege drop did not take effect: euid=%d egid=%d, want %d/%d",
			os.Geteuid(), os.Getegid(), uid, gid)
	}
	return nil
}
