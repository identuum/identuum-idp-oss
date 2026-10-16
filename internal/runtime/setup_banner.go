package runtime

import (
	"fmt"
	"io"

	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// writeSetupBanner prints URL + plaintext setup code + the local
// show-setup-code subcommand on every boot while status ==
// setup_required. The setup code is the wizard-authorisation
// credential, not an admin password (D-IDP-INSTALL-19), and is allowed
// in logs by the appliance install UX decisions (D-IDP-INSTALL-11).
// Operators with log-retention concerns can run
// `<binary> show-setup-code <data-dir>` (/app/identuum-idp in the
// image) to read the file directly.
func writeSetupBanner(w io.Writer, banner *setup.SetupBanner, isTerminal func(io.Writer) bool) {
	fmt.Fprintf(w,
		"identuum-idp: serve: first-run setup required — open %s\n",
		banner.SetupURL)
	fmt.Fprintf(w,
		"identuum-idp: serve: setup code (also stored at %s): %s\n",
		banner.TokenFilePath, banner.SetupToken)
	fmt.Fprintf(w,
		"identuum-idp: serve: to re-display the setup code later, run: %s\n",
		banner.ShowCodeCommand)
}

// setupOutputIsTerminal keeps the base behaviour: every destination
// receives the setup code.
func setupOutputIsTerminal(io.Writer) bool { return true }
