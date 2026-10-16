package runtime

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// writeSetupBanner prints the wizard URL and the local show-setup-code
// subcommand on every boot while status == setup_required. The
// plaintext setup code, the wizard-authorisation credential (not an
// admin password, D-IDP-INSTALL-19), is printed only when isTerminal
// reports w as a terminal (owner decision P-R2 option (b), 2026-10-16,
// superseding the log disclosure of D-IDP-INSTALL-11). Captured output
// (container logs, pipes, files) gets the command instead:
// `<binary> show-setup-code <data-dir>` (/app/identuum-idp in the image).
func writeSetupBanner(w io.Writer, banner *setup.SetupBanner, isTerminal func(io.Writer) bool) {
	fmt.Fprintf(w,
		"identuum-idp: serve: first-run setup required — open %s\n",
		banner.SetupURL)
	if !isTerminal(w) {
		fmt.Fprintf(w,
			"identuum-idp: serve: setup code not shown because stdout is not a terminal; to display it, run: %s\n",
			banner.ShowCodeCommand)
		return
	}
	fmt.Fprintf(w,
		"identuum-idp: serve: setup code (also stored at %s): %s\n",
		banner.TokenFilePath, banner.SetupToken)
	fmt.Fprintf(w,
		"identuum-idp: serve: to re-display the setup code later, run: %s\n",
		banner.ShowCodeCommand)
}

// setupOutputIsTerminal reports whether w is a terminal. Anything that
// is not an *os.File, or whose descriptor rejects the terminal
// window-size ioctl (a pipe, a regular file, /dev/null), fails closed.
func setupOutputIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	conn, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var ioctlErr error
	if err := conn.Control(func(fd uintptr) {
		_, ioctlErr = unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ)
	}); err != nil {
		return false
	}
	return ioctlErr == nil
}
