package runtime

// SIGNING-KEY-SEAL-1. An ACTIVE signing key that cannot be decrypted with the
// current at-rest key (IDENTUUM_IDP_ENCRYPTION_KEY) is a silent brick: the
// signer skips the undecryptable row (availability — one foreign row must not
// disable all signing), so tokens cannot be minted and every login fails,
// while /health — which reads only the StartupReport — stays green. The dev
// compose used to mint a fresh per-INSTANCE at-rest key when the env was
// empty, so any container recreate stranded every sealed row this way.
//
// The fix makes the state health-visible: at boot, if active/rotating rows
// exist but none are usable, record a FATAL StartupReport fault so /health
// reports NOT-SERVING with a named state and boot logs one unmissable line.

// signingKeySealFaultName is the StartupReport fault id for the seal state.
const signingKeySealFaultName = "signing-key-seal"

// signingKeySealFaultDetail is the operator-facing explanation attached to the
// fault and echoed once at boot.
const signingKeySealFaultDetail = "Active signing key(s) exist but NONE can be decrypted with the current " +
	"at-rest key (IDENTUUM_IDP_ENCRYPTION_KEY): tokens cannot be signed and every login will fail. " +
	"The key that sealed them differs from the current one — most often a fresh per-instance key minted " +
	"after a container recreate. Restore the original IDENTUUM_IDP_ENCRYPTION_KEY, or rotate the signing keys."

// signingKeySealFault reports the SIGNING-KEY-SEAL-1 brick state: one or more
// signing keys are in an active/rotating state (activeRows > 0) but NONE are
// usable/decryptable (usableKeys == 0). Zero active rows is a not-yet-set-up
// install, NOT a seal — a fresh database legitimately has no signing key until
// setup mints one, and that must stay healthy.
func signingKeySealFault(activeRows, usableKeys int) bool {
	return activeRows > 0 && usableKeys == 0
}
