package main

// The doctor subcommand (OPERATOR-UX-1) — a READ-ONLY, one-shot appliance
// diagnostic that prints NAMED states an operator can act on:
//
//	identuum-idp doctor [database-url]
//
//	version:          the build version
//	db:               ok | unreachable
//	at-rest-key:      present (source=env|env-compat|key-file) | invalid | absent
//	setup:            setup_required | setup_complete | unknown
//	signing-key-seal: ok | no-signing-keys | SEALED | cannot-evaluate | unknown
//
// Exit code 0 when healthy; non-zero with a FAILING line NAMING each failing
// state. The database URL follows the one-shot precedence (explicit positional
// wins, else IDENTUUM_IDP_DATABASE_URL, else IDENTUUM_IDP_OSS_DB — DSN-DEFAULT-1),
// so on a container that knows its own database the whole diagnosis is ONE
// flag-less `docker exec`.
//
// Strict no-leak rules:
//   - The database URL is never printed; open errors go through redactURL.
//   - Key MATERIAL is never printed — only the SOURCE name of the at-rest key.
//   - The seal probe decrypts in memory only (the same GetActiveSigningKeys
//     path the runtime uses); no key bytes reach stdout/stderr.
//
// The probe mirrors the serving runtime's SIGNING-KEY-SEAL-1 boot check
// (internal/runtime/runtime.go buildDeps): active/rotating rows counted via
// CountActiveSigningKeyRows, usable (decryptable) keys via
// GetActiveSigningKeys, sealed ⇔ rows exist but none are usable. Zero rows is
// a not-yet-set-up install, NOT a fault — setup mints the first key.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// doctorSetupReader is the narrow setup-state surface doctor needs.
// PgxSetupStateRepository satisfies it; tests pass fakes.
type doctorSetupReader interface {
	Get(ctx context.Context) (*domain.SetupState, error)
}

// doctorSealProber is the narrow signing-key surface doctor needs.
// *postgres.PgxKeyRepository satisfies it; tests pass fakes.
type doctorSealProber interface {
	CountActiveSigningKeyRows(ctx context.Context) (int, error)
	GetActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error)
}

// doctorDeps carries the resolved probes. Nil Setup/Seal mean the
// corresponding probe could not be constructed (no DB / no cipher) and the
// state is reported instead of probed.
type doctorDeps struct {
	Version string
	// DBOK is false when the pool could not be opened; every DB-backed state
	// is then unknown and "db" is the failing state that explains them.
	DBOK bool
	// AtRestKeySource is one of the atRestKeySource* names, or "invalid" when
	// key bytes were found but rejected by the cipher constructor.
	AtRestKeySource string
	Setup           doctorSetupReader
	Seal            doctorSealProber
}

// doctorCore prints one named state per line and returns the exit code:
// 0 healthy, 1 with a FAILING line naming each failing state. It never
// prints a database URL or key material.
func doctorCore(ctx context.Context, d doctorDeps, stdout io.Writer) int {
	var failing []string

	fmt.Fprintf(stdout, "identuum-idp: doctor: version: %s\n", d.Version)

	// db reachability.
	if d.DBOK {
		fmt.Fprintln(stdout, "identuum-idp: doctor: db: ok")
	} else {
		fmt.Fprintln(stdout, "identuum-idp: doctor: db: unreachable")
		failing = append(failing, "db")
	}

	// at-rest key mode. The SOURCE is named; the key itself never is.
	switch d.AtRestKeySource {
	case atRestKeySourceEnv, atRestKeySourceEnvCompat, atRestKeySourceKeyFile:
		fmt.Fprintf(stdout, "identuum-idp: doctor: at-rest-key: present (source=%s)\n", d.AtRestKeySource)
	case "invalid":
		fmt.Fprintln(stdout, "identuum-idp: doctor: at-rest-key: invalid (must be 32-byte hex)")
		failing = append(failing, "at-rest-key")
	default:
		fmt.Fprintln(stdout, "identuum-idp: doctor: at-rest-key: absent — set IDENTUUM_IDP_ENCRYPTION_KEY or mount the appliance data volume")
		failing = append(failing, "at-rest-key")
	}

	// setup state (needs the DB).
	switch {
	case d.Setup == nil:
		fmt.Fprintln(stdout, "identuum-idp: doctor: setup: unknown (database unreachable)")
	default:
		state, err := d.Setup.Get(ctx)
		switch {
		case errors.Is(err, domain.ErrSetupStateNotFound):
			fmt.Fprintln(stdout, "identuum-idp: doctor: setup: unknown (state row missing — is the database migrated?)")
			failing = append(failing, "setup-state")
		case err != nil:
			fmt.Fprintln(stdout, "identuum-idp: doctor: setup: unknown (state unreadable — is the database migrated?)")
			failing = append(failing, "setup-state")
		default:
			fmt.Fprintf(stdout, "identuum-idp: doctor: setup: %s\n", state.Status)
		}
	}

	// signing-key seal (needs the DB and a cipher).
	switch {
	case d.Seal == nil && d.DBOK:
		fmt.Fprintln(stdout, "identuum-idp: doctor: signing-key-seal: cannot-evaluate (no at-rest key)")
		// not appended: the at-rest-key state above already carries the fault
	case d.Seal == nil:
		fmt.Fprintln(stdout, "identuum-idp: doctor: signing-key-seal: unknown (database unreachable)")
	default:
		activeRows, err := d.Seal.CountActiveSigningKeyRows(ctx)
		if err != nil {
			fmt.Fprintln(stdout, "identuum-idp: doctor: signing-key-seal: unknown (count failed — is the database migrated?)")
			failing = append(failing, "signing-key-seal")
			break
		}
		if activeRows == 0 {
			// A fresh install legitimately has no signing key until setup
			// mints one — healthy, mirrors signingKeySealFault's zero-rows case.
			fmt.Fprintln(stdout, "identuum-idp: doctor: signing-key-seal: no-signing-keys (fresh install — setup mints the first key)")
			break
		}
		usable, err := d.Seal.GetActiveSigningKeys(ctx)
		if err != nil {
			fmt.Fprintln(stdout, "identuum-idp: doctor: signing-key-seal: unknown (load failed)")
			failing = append(failing, "signing-key-seal")
			break
		}
		if len(usable) == 0 {
			// The SIGNING-KEY-SEAL-1 brick state: rows exist, none decrypt.
			fmt.Fprintf(stdout, "identuum-idp: doctor: signing-key-seal: SEALED — %d active signing key(s) exist but NONE decrypt under the current at-rest key; tokens cannot be signed and every login fails. Restore the original IDENTUUM_IDP_ENCRYPTION_KEY, or rotate the signing keys.\n", activeRows)
			failing = append(failing, "signing-key-seal")
			break
		}
		fmt.Fprintf(stdout, "identuum-idp: doctor: signing-key-seal: ok (%d of %d active key(s) usable)\n", len(usable), activeRows)
	}

	if len(failing) > 0 {
		fmt.Fprintf(stdout, "identuum-idp: doctor: FAILING: %s\n", strings.Join(failing, ", "))
		return 1
	}
	fmt.Fprintln(stdout, "identuum-idp: doctor: healthy")
	return 0
}

// dispatchDoctor wires doctorCore to the real environment: resolves the DSN
// via the shared one-shot precedence, resolves the at-rest key source, opens
// the pool, and builds the probes. READ-ONLY: it constructs repositories and
// runs SELECTs only.
func dispatchDoctor(ctx context.Context, rest []string, stdout, stderr io.Writer) int {
	url, ok := requirePositionalURL("doctor", rest, stderr)
	if !ok {
		return 2
	}

	hexKey, source := resolveAtRestKey(os.Getenv, os.ReadFile)
	var cipher postgres.PrivateKeyCipher
	if hexKey != "" {
		cs, err := crypto.NewCryptoService(hexKey)
		if err != nil {
			source = "invalid"
		} else {
			cipher = cs
		}
	}

	deps := doctorDeps{Version: version, AtRestKeySource: source}
	pool, err := postgres.NewPool(ctx, url, nil)
	if err != nil {
		fmt.Fprintln(stderr, "identuum-idp: doctor: open pool failed:", redactURL(err, url))
		return doctorCore(ctx, deps, stdout)
	}
	defer pool.Close()
	deps.DBOK = true
	deps.Setup = postgres.NewPgxSetupStateRepository(pool)
	if cipher != nil {
		repos := postgres.NewPgxRepositories(pool, cipher)
		if repos != nil {
			if kr, ok := repos.Key.(*postgres.PgxKeyRepository); ok {
				deps.Seal = kr
			}
		}
	}
	return doctorCore(ctx, deps, stdout)
}
