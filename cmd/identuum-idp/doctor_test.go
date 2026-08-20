package main

// Unit coverage for the doctor subcommand (OPERATOR-UX-1 / DOCTOR-1).
// Hermetic: doctorCore takes fakes; no Postgres, no env, no network.
// The one dispatch-level case exercises only the no-DSN refusal.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type fakeDoctorSetup struct {
	state *domain.SetupState
	err   error
}

func (f fakeDoctorSetup) Get(context.Context) (*domain.SetupState, error) {
	return f.state, f.err
}

type fakeDoctorSeal struct {
	rows      int
	rowsErr   error
	usable    []domain.SigningKey
	usableErr error
}

func (f fakeDoctorSeal) CountActiveSigningKeyRows(context.Context) (int, error) {
	return f.rows, f.rowsErr
}

func (f fakeDoctorSeal) GetActiveSigningKeys(context.Context) ([]domain.SigningKey, error) {
	return f.usable, f.usableErr
}

// RULE: DOCTOR-1
func TestDoctorCore_NamedStatesAndExitCodes(t *testing.T) {
	ctx := context.Background()

	t.Run("healthy install exits 0 with every state named", func(t *testing.T) {
		var out bytes.Buffer
		rc := doctorCore(ctx, doctorDeps{
			Version:         "identuum-idp-oss test",
			DBOK:            true,
			AtRestKeySource: atRestKeySourceEnv,
			Setup:           fakeDoctorSetup{state: &domain.SetupState{Status: domain.SetupStatusComplete}},
			Seal:            fakeDoctorSeal{rows: 2, usable: make([]domain.SigningKey, 2)},
		}, &out)
		if rc != 0 {
			t.Fatalf("healthy exit = %d, want 0\n%s", rc, out.String())
		}
		for _, want := range []string{
			"version: identuum-idp-oss test",
			"db: ok",
			"at-rest-key: present (source=env)",
			"setup: setup_complete",
			"signing-key-seal: ok (2 of 2 active key(s) usable)",
			"doctor: healthy",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("healthy output must contain %q; got:\n%s", want, out.String())
			}
		}
		if strings.Contains(out.String(), "FAILING") {
			t.Errorf("healthy output must not contain FAILING; got:\n%s", out.String())
		}
	})

	t.Run("sealed signing keys exit non-zero NAMING signing-key-seal", func(t *testing.T) {
		var out bytes.Buffer
		rc := doctorCore(ctx, doctorDeps{
			Version:         "v",
			DBOK:            true,
			AtRestKeySource: atRestKeySourceKeyFile,
			Setup:           fakeDoctorSetup{state: &domain.SetupState{Status: domain.SetupStatusComplete}},
			Seal:            fakeDoctorSeal{rows: 2, usable: nil}, // rows exist, none decrypt
		}, &out)
		if rc == 0 {
			t.Fatalf("sealed install must exit non-zero\n%s", out.String())
		}
		if !strings.Contains(out.String(), "signing-key-seal: SEALED") {
			t.Errorf("sealed output must name the SEALED state; got:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "FAILING: signing-key-seal") {
			t.Errorf("FAILING line must name signing-key-seal; got:\n%s", out.String())
		}
	})

	t.Run("fresh install (zero signing keys, setup_required) is HEALTHY", func(t *testing.T) {
		var out bytes.Buffer
		rc := doctorCore(ctx, doctorDeps{
			Version:         "v",
			DBOK:            true,
			AtRestKeySource: atRestKeySourceEnv,
			Setup:           fakeDoctorSetup{state: &domain.SetupState{Status: domain.SetupStatusRequired}},
			Seal:            fakeDoctorSeal{rows: 0},
		}, &out)
		if rc != 0 {
			t.Fatalf("fresh install exit = %d, want 0 (setup_required is a state, not a fault)\n%s", rc, out.String())
		}
		if !strings.Contains(out.String(), "setup: setup_required") {
			t.Errorf("output must name setup_required; got:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "signing-key-seal: no-signing-keys") {
			t.Errorf("output must name the no-signing-keys state; got:\n%s", out.String())
		}
	})

	t.Run("absent at-rest key exits non-zero NAMING at-rest-key", func(t *testing.T) {
		var out bytes.Buffer
		rc := doctorCore(ctx, doctorDeps{
			Version:         "v",
			DBOK:            true,
			AtRestKeySource: atRestKeySourceAbsent,
			Setup:           fakeDoctorSetup{state: &domain.SetupState{Status: domain.SetupStatusRequired}},
			Seal:            nil, // no cipher, no prober
		}, &out)
		if rc == 0 {
			t.Fatalf("absent at-rest key must exit non-zero\n%s", out.String())
		}
		if !strings.Contains(out.String(), "FAILING: at-rest-key") {
			t.Errorf("FAILING line must name at-rest-key; got:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "signing-key-seal: cannot-evaluate") {
			t.Errorf("seal state must be cannot-evaluate without a cipher; got:\n%s", out.String())
		}
	})

	t.Run("unreachable database exits non-zero NAMING db", func(t *testing.T) {
		var out bytes.Buffer
		rc := doctorCore(ctx, doctorDeps{
			Version:         "v",
			DBOK:            false,
			AtRestKeySource: atRestKeySourceEnv,
		}, &out)
		if rc == 0 {
			t.Fatalf("unreachable DB must exit non-zero\n%s", out.String())
		}
		for _, want := range []string{"db: unreachable", "FAILING: db", "setup: unknown", "signing-key-seal: unknown"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("output must contain %q; got:\n%s", want, out.String())
			}
		}
	})

	t.Run("unmigrated database names setup-state as failing", func(t *testing.T) {
		var out bytes.Buffer
		rc := doctorCore(ctx, doctorDeps{
			Version:         "v",
			DBOK:            true,
			AtRestKeySource: atRestKeySourceEnv,
			Setup:           fakeDoctorSetup{err: domain.ErrSetupStateNotFound},
			Seal:            fakeDoctorSeal{rows: 0},
		}, &out)
		if rc == 0 {
			t.Fatalf("missing setup-state row must exit non-zero\n%s", out.String())
		}
		if !strings.Contains(out.String(), "FAILING: setup-state") {
			t.Errorf("FAILING line must name setup-state; got:\n%s", out.String())
		}
	})
}

// doctor with no positional URL and no env DSN refuses with the shared
// usage error (no DB is contacted).
func TestDispatchDoctor_RequiresDSN(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_DATABASE_URL", "")
	t.Setenv("IDENTUUM_IDP_OSS_DB", "")
	var stdout, stderr bytes.Buffer
	rc := dispatchDoctor(context.Background(), nil, &stdout, &stderr)
	if rc != 2 {
		t.Fatalf("doctor with no DSN anywhere exit = %d, want 2", rc)
	}
	if !strings.Contains(stderr.String(), "IDENTUUM_IDP_DATABASE_URL") {
		t.Fatalf("refusal must name the env fallback; got %q", stderr.String())
	}
}
