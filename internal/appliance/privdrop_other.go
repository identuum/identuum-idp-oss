//go:build !linux

package appliance

import (
	"fmt"
	"os"
)

// The appliance entrypoint targets the Linux container image. These stubs keep
// the package building — and its logic testable — on a developer's macOS
// machine, without pretending a privilege drop happened.

func IsRoot() bool { return os.Geteuid() == 0 }

func Chown(path string, uid, gid int) error { return os.Chown(path, uid, gid) }

// DropPrivileges REFUSES rather than silently succeeding when it is actually
// needed. Returning nil here would mean a non-Linux build running as root
// serves as root while the log says it dropped.
func DropPrivileges(uid, gid int) error {
	if !IsRoot() {
		return nil
	}
	return fmt.Errorf("appliance: running as root on a non-Linux platform, where this build "+
		"cannot drop privileges to uid=%d gid=%d — refusing to serve as root", uid, gid)
}
