package service

// webauthn_service_test.go — service-layer tests for the OSS
// WebAuthn port. Covered:
//
//   - challenge persistence + TTL on BeginRegistration / BeginLogin;
//   - challenge consume-on-finish (single use, including failures);
//   - tenant isolation guard on FinishLogin;
//   - persisted clone-warning hard rejection;
//   - ListCredentials proxy + FindUserByEmail anti-enumeration;
//   - DeleteCredential ownership guard;
//   - BeginLogin returns ErrWebAuthnNoCredentials when the user
//     has zero stored credentials;
//   - BeginDummyLogin returns a structurally complete assertion +
//     opaque session id with no side effects on the store.
//
// We do NOT test the upstream go-webauthn library's cryptographic
// verification — that would require a virtual authenticator and
// belongs in a Playwright browser-level test. The library is
// stubbed via webAuthnValidator so each test forces the canned
// outcome it needs.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// ---------- shared test fixtures ----------

// stubValidator is the test-only implementation of webAuthnValidator.
// Each function pointer is consulted on the matching call; nil
// pointers panic so accidental new dependencies surface as test
// failures.
type stubValidator struct {
	beginReg    func(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	finishReg   func(user webauthn.User, session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error)
	beginLogin  func(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	finishLogin func(user webauthn.User, session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error)
}

func (s *stubValidator) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return s.beginReg(user, opts...)
}
func (s *stubValidator) FinishRegistration(user webauthn.User, session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error) {
	return s.finishReg(user, session, request)
}
func (s *stubValidator) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return s.beginLogin(user, opts...)
}
func (s *stubValidator) FinishLogin(user webauthn.User, session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error) {
	return s.finishLogin(user, session, request)
}

// memUserRepoForWebAuthn satisfies the WebAuthnUserRepo seam.
type memUserRepoForWebAuthn struct {
	byID    map[uuid.UUID]*domain.User
	byEmail map[string][]*domain.User
}

func newMemUserRepoForWebAuthn(users ...*domain.User) *memUserRepoForWebAuthn {
	repo := &memUserRepoForWebAuthn{
		byID:    make(map[uuid.UUID]*domain.User, len(users)),
		byEmail: make(map[string][]*domain.User),
	}
	for _, u := range users {
		repo.byID[u.ID] = u
		repo.byEmail[u.Email] = append(repo.byEmail[u.Email], u)
	}
	return repo
}

func (r *memUserRepoForWebAuthn) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if u, ok := r.byID[id]; ok {
		return u, nil
	}
	return nil, domain.ErrResourceNotFound
}

func (r *memUserRepoForWebAuthn) FindUsersByEmail(_ context.Context, email string) ([]*domain.User, error) {
	if us, ok := r.byEmail[email]; ok {
		out := make([]*domain.User, len(us))
		copy(out, us)
		return out, nil
	}
	return nil, nil
}

// memCredRepo satisfies repository.WebAuthnCredentialRepository.
type memCredRepo struct {
	mu          sync.Mutex
	byUser      map[uuid.UUID][]*domain.WebAuthnCredential
	byCredID    map[string]*domain.WebAuthnCredential
	signUpdates int
	updateClone func(uuid.UUID, bool) error
}

func newMemCredRepo() *memCredRepo {
	return &memCredRepo{
		byUser:   make(map[uuid.UUID][]*domain.WebAuthnCredential),
		byCredID: make(map[string]*domain.WebAuthnCredential),
	}
}

func (r *memCredRepo) Create(_ context.Context, cred *domain.WebAuthnCredential) (*domain.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cred.ID == uuid.Nil {
		cred.ID = uuid.New()
	}
	r.byUser[cred.UserID] = append(r.byUser[cred.UserID], cred)
	r.byCredID[string(cred.CredentialID)] = cred
	return cred, nil
}

func (r *memCredRepo) GetByCredentialID(_ context.Context, credentialID []byte) (*domain.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.byCredID[string(credentialID)]; ok {
		return c, nil
	}
	return nil, repository.ErrWebAuthnCredentialNotFound
}

func (r *memCredRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]*domain.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.byUser[userID]
	if out == nil {
		return nil, nil
	}
	cp := make([]*domain.WebAuthnCredential, len(out))
	copy(cp, out)
	return cp, nil
}

func (r *memCredRepo) UpdateSignCount(_ context.Context, id uuid.UUID, newCount uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signUpdates++
	for _, list := range r.byUser {
		for _, c := range list {
			if c.ID == id {
				c.SignCount = newCount
				return nil
			}
		}
	}
	return nil
}

func (r *memCredRepo) UpdateLastUsed(_ context.Context, id uuid.UUID) error { return nil }

func (r *memCredRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for uid, list := range r.byUser {
		filtered := list[:0]
		for _, c := range list {
			if c.ID == id {
				delete(r.byCredID, string(c.CredentialID))
				continue
			}
			filtered = append(filtered, c)
		}
		r.byUser[uid] = filtered
	}
	return nil
}

func (r *memCredRepo) UpdateCloneWarning(ctx context.Context, id uuid.UUID, warning bool) error {
	if r.updateClone != nil {
		return r.updateClone(id, warning)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, list := range r.byUser {
		for _, c := range list {
			if c.ID == id {
				c.CloneWarning = warning
				return nil
			}
		}
	}
	return nil
}

// auditRecorder satisfies audit.Service and stores every event for
// assertion. Safe for concurrent use.
type auditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *auditRecorder) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *auditRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

// newWebAuthnServiceFixture wires a *WebAuthnService directly,
// bypassing NewWebAuthnService (whose constructor stands up the
// upstream library config which we do not need for these tests).
// The test fixture uses the stub validator so we can force any
// upstream outcome.
type webAuthnFixture struct {
	svc        *WebAuthnService
	validator  *stubValidator
	credRepo   *memCredRepo
	sessionRep *repository.InMemoryWebAuthnSessionRepository
	user       *domain.User
	audit      *auditRecorder
}

func newWebAuthnFixture(t *testing.T) *webAuthnFixture {
	t.Helper()
	orgID := uuid.New()
	uid, _ := uuid.NewV7()
	user := &domain.User{
		ID:             uid,
		Email:          "fixture@example.test",
		Role:           domain.RoleOrgUser,
		OrganizationID: orgID,
	}
	userRepo := newMemUserRepoForWebAuthn(user)
	credRepo := newMemCredRepo()
	sessionRepo := repository.NewInMemoryWebAuthnSessionRepository()
	validator := &stubValidator{}
	recorder := &auditRecorder{}
	svc := &WebAuthnService{
		validator:   validator,
		userRepo:    userRepo,
		credRepo:    credRepo,
		sessionRepo: sessionRepo,
		audit:       recorder,
		logger:      zap.NewNop(),
	}
	return &webAuthnFixture{
		svc:        svc,
		validator:  validator,
		credRepo:   credRepo,
		sessionRep: sessionRepo,
		user:       user,
		audit:      recorder,
	}
}

// ---------- tests ----------

// TestBeginRegistration_PersistsChallengeReturnsSessionID asserts
// the happy path: a fresh session is persisted to the repo and the
// returned session_id resolves to a non-nil SessionData.
func TestBeginRegistration_PersistsChallengeReturnsSessionID(t *testing.T) {
	f := newWebAuthnFixture(t)
	wantSession := &webauthn.SessionData{Challenge: "challenge-bytes", UserID: f.user.ID[:]}
	f.validator.beginReg = func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
		return &protocol.CredentialCreation{}, wantSession, nil
	}
	creation, sessionID, err := f.svc.BeginRegistration(context.Background(), f.user)
	require.NoError(t, err)
	require.NotNil(t, creation)
	require.NotEmpty(t, sessionID)

	stored, err := f.sessionRep.Get(context.Background(), registrationKey(sessionID))
	require.NoError(t, err)
	assert.Equal(t, "challenge-bytes", stored.Challenge)
}

// TestFinishRegistration_RejectsMissingSession asserts the empty
// session id is rejected with ErrWebAuthnSessionInvalid.
func TestFinishRegistration_RejectsMissingSession(t *testing.T) {
	f := newWebAuthnFixture(t)
	_, err := f.svc.FinishRegistration(context.Background(), f.user, "", httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnSessionInvalid)
}

// TestFinishRegistration_RejectsUnknownSession asserts that a
// session id with no stored entry is rejected.
func TestFinishRegistration_RejectsUnknownSession(t *testing.T) {
	f := newWebAuthnFixture(t)
	_, err := f.svc.FinishRegistration(context.Background(), f.user, "no-such-id", httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnSessionInvalid)
}

// TestFinishRegistration_ConsumesSessionOnSuccess asserts the
// session row is gone after a successful Finish — preventing
// replay of the same session id.
func TestFinishRegistration_ConsumesSessionOnSuccess(t *testing.T) {
	f := newWebAuthnFixture(t)
	f.validator.beginReg = func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
		return &protocol.CredentialCreation{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	credBytes := []byte{0x01, 0x02, 0x03}
	f.validator.finishReg = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return &webauthn.Credential{
			ID:              credBytes,
			PublicKey:       []byte{0xAA, 0xBB},
			AttestationType: "none",
			Transport:       []protocol.AuthenticatorTransport{protocol.Internal},
		}, nil
	}
	_, sessionID, err := f.svc.BeginRegistration(context.Background(), f.user)
	require.NoError(t, err)
	_, err = f.svc.FinishRegistration(context.Background(), f.user, sessionID, httpReq(t))
	require.NoError(t, err)

	// Session row must be gone after Finish — replay would otherwise succeed.
	_, getErr := f.sessionRep.Get(context.Background(), registrationKey(sessionID))
	assert.Error(t, getErr)

	// Credential is persisted.
	creds, err := f.credRepo.ListByUser(context.Background(), f.user.ID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, credBytes, creds[0].CredentialID)
	assert.Equal(t, f.user.OrganizationID, creds[0].OrganizationID)

	// Audit event emitted.
	events := f.audit.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(domain.AuditWebAuthnCredentialRegistered), events[0].Action)
	assert.Equal(t, "success", events[0].Outcome)
}

// TestFinishRegistration_ConsumesSessionOnLibraryFailure asserts
// the session row is dropped even when the upstream library
// rejects the attestation — a malformed retry MUST NOT replay the
// same challenge.
func TestFinishRegistration_ConsumesSessionOnLibraryFailure(t *testing.T) {
	f := newWebAuthnFixture(t)
	f.validator.beginReg = func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
		return &protocol.CredentialCreation{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	f.validator.finishReg = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return nil, errors.New("attestation invalid")
	}
	_, sessionID, err := f.svc.BeginRegistration(context.Background(), f.user)
	require.NoError(t, err)
	_, err = f.svc.FinishRegistration(context.Background(), f.user, sessionID, httpReq(t))
	require.Error(t, err)

	_, getErr := f.sessionRep.Get(context.Background(), registrationKey(sessionID))
	assert.Error(t, getErr, "challenge must be consumed even on library failure")

	// Credential NOT persisted.
	creds, _ := f.credRepo.ListByUser(context.Background(), f.user.ID)
	assert.Len(t, creds, 0)
}

// TestBeginLogin_RejectsZeroCredentials asserts the
// ErrWebAuthnNoCredentials sentinel fires when the user has no
// stored credentials. The handler maps it onto the dummy-assertion
// path for anti-enumeration.
func TestBeginLogin_RejectsZeroCredentials(t *testing.T) {
	f := newWebAuthnFixture(t)
	_, _, err := f.svc.BeginLogin(context.Background(), f.user)
	assert.ErrorIs(t, err, ErrWebAuthnNoCredentials)
}

// TestBeginLogin_PersistsChallengeReturnsSessionID exercises the
// happy path of the login ceremony begin.
func TestBeginLogin_PersistsChallengeReturnsSessionID(t *testing.T) {
	f := newWebAuthnFixture(t)
	seedCredential(t, f, []byte{0x01})
	wantSession := &webauthn.SessionData{Challenge: "login-c", UserID: f.user.ID[:]}
	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, wantSession, nil
	}
	assertion, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	require.NotNil(t, assertion)
	require.NotEmpty(t, sessionID)

	stored, err := f.sessionRep.Get(context.Background(), loginKey(sessionID))
	require.NoError(t, err)
	assert.Equal(t, "login-c", stored.Challenge)
}

// TestFinishLogin_RejectsUnknownSession asserts an opaque session
// id with no stored entry is rejected.
func TestFinishLogin_RejectsUnknownSession(t *testing.T) {
	f := newWebAuthnFixture(t)
	_, _, _, err := f.svc.FinishLogin(context.Background(), "missing", httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnSessionInvalid)
}

// TestFinishLogin_SuccessUpdatesSignCount asserts a clean success
// updates the persisted sign_count and returns the credential +
// user.
func TestFinishLogin_SuccessUpdatesSignCount(t *testing.T) {
	f := newWebAuthnFixture(t)
	credBytes := []byte{0x10, 0x11}
	stored := seedCredential(t, f, credBytes)

	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "lc"}, nil
	}
	f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return &webauthn.Credential{
			ID: credBytes,
			Authenticator: webauthn.Authenticator{
				SignCount: stored.SignCount + 1,
			},
		}, nil
	}
	_, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	cred, user, _, err := f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	require.NoError(t, err)
	require.NotNil(t, cred)
	require.NotNil(t, user)
	assert.Equal(t, f.user.ID, user.ID)
	assert.Equal(t, stored.ID, cred.ID)
	assert.GreaterOrEqual(t, f.credRepo.signUpdates, 1)
}

// TestFinishLogin_ConsumesSessionOnSuccess asserts that a single
// login session id cannot be replayed even on a clean success.
func TestFinishLogin_ConsumesSessionOnSuccess(t *testing.T) {
	f := newWebAuthnFixture(t)
	credBytes := []byte{0x21}
	seedCredential(t, f, credBytes)
	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return &webauthn.Credential{ID: credBytes, Authenticator: webauthn.Authenticator{SignCount: 1}}, nil
	}
	_, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	_, _, _, err = f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	require.NoError(t, err)

	// Second attempt must fail — session was consumed.
	_, _, _, err = f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnSessionInvalid)
}

// TestFinishLogin_PersistedCloneWarningRejects pins the §1.10
// persistence-state clone guard: a credential previously flagged
// CloneWarning=true MUST NOT authenticate again.
func TestFinishLogin_PersistedCloneWarningRejects(t *testing.T) {
	f := newWebAuthnFixture(t)
	credBytes := []byte{0x31}
	stored := seedCredential(t, f, credBytes)
	stored.CloneWarning = true

	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return &webauthn.Credential{ID: credBytes, Authenticator: webauthn.Authenticator{SignCount: 1}}, nil
	}
	_, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	_, _, _, err = f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnCloneDetected)
}

// TestFinishLogin_LiveCloneWarningFlagsCredential pins that the
// upstream library's CloneWarning verdict is persisted on the
// stored row so subsequent attempts are blocked by the
// persistence-state guard.
func TestFinishLogin_LiveCloneWarningFlagsCredential(t *testing.T) {
	f := newWebAuthnFixture(t)
	credBytes := []byte{0x41}
	stored := seedCredential(t, f, credBytes)

	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return &webauthn.Credential{
			ID: credBytes,
			Authenticator: webauthn.Authenticator{
				CloneWarning: true,
			},
		}, nil
	}
	_, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	_, _, _, err = f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnCloneDetected)
	// Stored row must now carry the warning.
	assert.True(t, stored.CloneWarning, "row must be flagged CloneWarning=true after live detection")
}

// TestFinishLogin_TenantMismatchRejects asserts the credential's
// organization must match the user's organization.
func TestFinishLogin_TenantMismatchRejects(t *testing.T) {
	f := newWebAuthnFixture(t)
	credBytes := []byte{0x51}
	stored := seedCredential(t, f, credBytes)
	stored.OrganizationID = uuid.New() // mutate to a different org

	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return &webauthn.Credential{ID: credBytes}, nil
	}
	_, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	_, _, _, err = f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnTenantMismatch)
}

// TestFinishLogin_LibraryRejectionIsAssertionInvalid asserts that
// a library-side verification failure collapses onto the
// ErrWebAuthnAssertionInvalid sentinel — not a 500.
func TestFinishLogin_LibraryRejectionIsAssertionInvalid(t *testing.T) {
	f := newWebAuthnFixture(t)
	seedCredential(t, f, []byte{0x61})
	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return nil, errors.New("library says no")
	}
	_, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	_, _, _, err = f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnAssertionInvalid)
}

// TestFinishLogin_UnknownCredentialMaps asserts the
// ErrWebAuthnCredentialMissing sentinel fires when the library
// verified an assertion but the credential id is not in the OSS
// store. The handler maps this to 401.
func TestFinishLogin_UnknownCredentialMaps(t *testing.T) {
	f := newWebAuthnFixture(t)
	seedCredential(t, f, []byte{0x71})
	f.validator.beginLogin = func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
		return &protocol.CredentialAssertion{}, &webauthn.SessionData{UserID: f.user.ID[:], Challenge: "c"}, nil
	}
	f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
		return &webauthn.Credential{ID: []byte{0xFF}}, nil // not in store
	}
	_, sessionID, err := f.svc.BeginLogin(context.Background(), f.user)
	require.NoError(t, err)
	_, _, _, err = f.svc.FinishLogin(context.Background(), sessionID, httpReq(t))
	assert.ErrorIs(t, err, ErrWebAuthnCredentialMissing)
}

// TestDelete_OwnershipEnforced asserts that a credential cannot be
// deleted by a non-owner. Returns domain.ErrResourceNotFound (which
// the handler maps to 404, avoiding enumeration of credential ids
// across users).
func TestDelete_OwnershipEnforced(t *testing.T) {
	f := newWebAuthnFixture(t)
	credBytes := []byte{0x81}
	stored := seedCredential(t, f, credBytes)

	otherUser := uuid.New()
	err := f.svc.DeleteCredential(context.Background(), otherUser, stored.ID)
	assert.ErrorIs(t, err, domain.ErrResourceNotFound)

	// Credential still present.
	creds, _ := f.credRepo.ListByUser(context.Background(), f.user.ID)
	assert.Len(t, creds, 1)

	// Owner can delete.
	err = f.svc.DeleteCredential(context.Background(), f.user.ID, stored.ID)
	require.NoError(t, err)
	after, _ := f.credRepo.ListByUser(context.Background(), f.user.ID)
	assert.Len(t, after, 0)

	// Audit event emitted for the successful delete.
	events := f.audit.snapshot()
	assert.Equal(t, string(domain.AuditWebAuthnCredentialDeleted), events[len(events)-1].Action)
}

// TestDelete_NilArgumentsRejected pins the defensive zero-value
// guard.
func TestDelete_NilArgumentsRejected(t *testing.T) {
	f := newWebAuthnFixture(t)
	err := f.svc.DeleteCredential(context.Background(), uuid.Nil, uuid.New())
	assert.ErrorIs(t, err, domain.ErrResourceNotFound)
	err = f.svc.DeleteCredential(context.Background(), uuid.New(), uuid.Nil)
	assert.ErrorIs(t, err, domain.ErrResourceNotFound)
}

// TestListCredentials_Proxies asserts the service proxies through
// to the repository — the handler relies on this.
func TestListCredentials_Proxies(t *testing.T) {
	f := newWebAuthnFixture(t)
	seedCredential(t, f, []byte{0xA0})
	got, err := f.svc.ListCredentials(context.Background(), f.user.ID)
	require.NoError(t, err)
	require.Len(t, got, 1)
}

// TestFindUserByEmail_AntiEnumerationContract asserts the contract
// the handler relies on for anti-enumeration: ONE match returns
// the user; ZERO or MORE-THAN-ONE returns (nil, nil).
func TestFindUserByEmail_AntiEnumerationContract(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()
	uid1, _ := uuid.NewV7()
	uid2, _ := uuid.NewV7()
	user1 := &domain.User{ID: uid1, Email: "shared@example.test", OrganizationID: orgA, Role: domain.RoleOrgUser}
	user2 := &domain.User{ID: uid2, Email: "shared@example.test", OrganizationID: orgB, Role: domain.RoleOrgUser}

	svc := &WebAuthnService{
		userRepo: newMemUserRepoForWebAuthn(user1, user2),
		credRepo: newMemCredRepo(),
		audit:    audit.NoopService{},
		logger:   zap.NewNop(),
	}
	// Two matches → (nil, nil) so the handler routes to dummy.
	u, err := svc.FindUserByEmail(context.Background(), "shared@example.test")
	require.NoError(t, err)
	assert.Nil(t, u)

	// Zero matches → (nil, nil).
	u, err = svc.FindUserByEmail(context.Background(), "absent@example.test")
	require.NoError(t, err)
	assert.Nil(t, u)

	// One match → returns the row.
	soloID, _ := uuid.NewV7()
	solo := &domain.User{ID: soloID, Email: "solo@example.test", OrganizationID: orgA, Role: domain.RoleOrgUser}
	svc.userRepo = newMemUserRepoForWebAuthn(solo)
	u, err = svc.FindUserByEmail(context.Background(), "solo@example.test")
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, solo.ID, u.ID)
}

// TestBeginDummyLogin_StructuralShape asserts the dummy assertion
// has the same shape a real BeginLogin would produce. This is
// load-bearing for anti-enumeration: a structurally distinct
// dummy would be an oracle.
func TestBeginDummyLogin_StructuralShape(t *testing.T) {
	f := newWebAuthnFixture(t)
	assertion, sessionID := f.svc.BeginDummyLogin(context.Background())
	require.NotNil(t, assertion)
	require.NotEmpty(t, sessionID)
	require.NotEmpty(t, assertion.Response.Challenge)
	require.Len(t, assertion.Response.AllowedCredentials, 1)
	assert.Equal(t, protocol.PublicKeyCredentialType, assertion.Response.AllowedCredentials[0].Type)
	assert.Equal(t, protocol.VerificationPreferred, assertion.Response.UserVerification)

	// MUST NOT persist a session row for the dummy path.
	_, err := f.sessionRep.Get(context.Background(), loginKey(sessionID))
	assert.Error(t, err)
}

// TestSessionTTLConstant pins the documented 5-minute TTL —
// drifting it requires an explicit security review.
func TestSessionTTLConstant(t *testing.T) {
	assert.Equal(t, 5*time.Minute, WebAuthnTTL)
}

// TestNormalizeUIOriginForRPID covers each branch of the
// origin-compatibility helper.
func TestNormalizeUIOriginForRPID(t *testing.T) {
	cases := []struct {
		name       string
		ui, rpID   string
		wantOrigin string
		wantOK     bool
	}{
		{"empty ui", "", "auth.example.com", "", false},
		{"empty rp", "https://ui.example.com", "", "", false},
		{"bad scheme", "ftp://ui.example.com", "ui.example.com", "", false},
		{"empty host", "https://", "ui.example.com", "", false},
		{"exact host match", "https://auth.example.com", "auth.example.com", "https://auth.example.com", true},
		{"subdomain match", "https://ui.auth.example.com", "auth.example.com", "https://ui.auth.example.com", true},
		{"unrelated host rejected", "https://attacker.com", "auth.example.com", "", false},
		{"port-bearing host", "https://localhost:7104", "localhost", "https://localhost:7104", true},
		// Local split-runtime dev shape: identuum-ui is served over
		// plaintext HTTP on port 7104 while the IDP runs on
		// http://localhost:7113. The cmd/identuum-idp resolver picks
		// http://localhost:7104 as the WebAuthn UI origin default; the
		// normalizer must accept it against an rpID of "localhost".
		{"local-dev http UI port matches localhost rp_id", "http://localhost:7104", "localhost", "http://localhost:7104", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotOrigin, gotOK := normalizeUIOriginForRPID(c.ui, c.rpID)
			assert.Equal(t, c.wantOrigin, gotOrigin)
			assert.Equal(t, c.wantOK, gotOK)
		})
	}
}

// TestNewWebAuthnService_RequiredFields asserts the constructor
// rejects nil repos and a missing BaseURL.
func TestNewWebAuthnService_RequiredFields(t *testing.T) {
	credRepo := newMemCredRepo()
	sessionRepo := repository.NewInMemoryWebAuthnSessionRepository()
	userRepo := newMemUserRepoForWebAuthn()

	_, err := NewWebAuthnService(WebAuthnServiceConfig{BaseURL: "http://localhost", UserRepo: nil, CredRepo: credRepo, SessionRepo: sessionRepo})
	assert.Error(t, err)
	_, err = NewWebAuthnService(WebAuthnServiceConfig{BaseURL: "http://localhost", UserRepo: userRepo, CredRepo: nil, SessionRepo: sessionRepo})
	assert.Error(t, err)
	_, err = NewWebAuthnService(WebAuthnServiceConfig{BaseURL: "http://localhost", UserRepo: userRepo, CredRepo: credRepo, SessionRepo: nil})
	assert.Error(t, err)
	_, err = NewWebAuthnService(WebAuthnServiceConfig{UserRepo: userRepo, CredRepo: credRepo, SessionRepo: sessionRepo})
	assert.Error(t, err)

	svc, err := NewWebAuthnService(WebAuthnServiceConfig{BaseURL: "http://localhost", UserRepo: userRepo, CredRepo: credRepo, SessionRepo: sessionRepo})
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// TestNewWebAuthnService_AcceptsLocalDevUIOrigin pins the local
// split-runtime configuration shape exercised by cmd/identuum-idp
// when the IDP runs on http://localhost:7113 and identuum-ui runs on
// http://localhost:7104. The constructor must accept the pair so
// passkey ceremonies originating from the UI port can pass go-webauthn's
// exact-host origin check.
func TestNewWebAuthnService_AcceptsLocalDevUIOrigin(t *testing.T) {
	credRepo := newMemCredRepo()
	sessionRepo := repository.NewInMemoryWebAuthnSessionRepository()
	userRepo := newMemUserRepoForWebAuthn()

	svc, err := NewWebAuthnService(WebAuthnServiceConfig{
		BaseURL:         "http://localhost:7113",
		UIPublicBaseURL: "http://localhost:7104",
		UserRepo:        userRepo,
		CredRepo:        credRepo,
		SessionRepo:     sessionRepo,
	})
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// TestNewWebAuthnService_DropsMismatchedUIOrigin pins the silent
// drop posture documented on WebAuthnServiceConfig: a UI origin that
// is not RP-ID-compatible (here, a public host versus a localhost
// rp_id) must NOT cause the constructor to fail — the service stays
// up with the IDP origin alone in RPOrigins. Without this posture,
// an operator-misconfigured override would take the whole WebAuthn
// surface down.
func TestNewWebAuthnService_DropsMismatchedUIOrigin(t *testing.T) {
	credRepo := newMemCredRepo()
	sessionRepo := repository.NewInMemoryWebAuthnSessionRepository()
	userRepo := newMemUserRepoForWebAuthn()

	svc, err := NewWebAuthnService(WebAuthnServiceConfig{
		BaseURL:         "http://localhost:7113",
		UIPublicBaseURL: "https://attacker.example.com",
		UserRepo:        userRepo,
		CredRepo:        credRepo,
		SessionRepo:     sessionRepo,
	})
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// ---------- helpers ----------

func httpReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/", nil)
	require.NoError(t, err)
	return req
}

// TestFinishLogin_ConcurrentSingleUse (P2-11) drives the fix at the
// SERVICE level: many concurrent FinishLogin calls for the SAME sessionID
// must see EXACTLY ONE winner get past the atomic Consume; every other
// call gets ErrWebAuthnSessionInvalid (the session is already gone). The
// winner reaches the (stubbed) validator, so its outcome is any
// NON-session-invalid result — that is the "consumed the session" signal.
// TEETH: route the service back through Get + defer-Delete and, under
// -race, more than one call gets past Consume (replay).
func TestFinishLogin_ConcurrentSingleUse(t *testing.T) {
	const goroutines = 48
	const rounds = 20
	for round := 0; round < rounds; round++ {
		f := newWebAuthnFixture(t)
		// Deterministic winner path: the validator returns an error, so the
		// single call that consumes the session returns a NON-session-invalid
		// error without needing full downstream success wiring.
		f.validator.finishLogin = func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return nil, errors.New("stub finish login")
		}
		const sid = "same-login-session"
		require.NoError(t, f.sessionRep.Save(context.Background(), loginKey(sid),
			&webauthn.SessionData{Challenge: "c", UserID: f.user.ID[:]}, time.Minute))

		var pastConsume, invalid int64
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer done.Done()
				start.Wait()
				_, _, _, err := f.svc.FinishLogin(context.Background(), sid, httpReq(t))
				if errors.Is(err, ErrWebAuthnSessionInvalid) {
					atomic.AddInt64(&invalid, 1)
				} else {
					atomic.AddInt64(&pastConsume, 1) // got the session (winner path)
				}
			}()
		}
		start.Done()
		done.Wait()
		if pastConsume != 1 {
			t.Fatalf("round %d: service single-use VIOLATED — %d calls consumed one session, want exactly 1 (assertion replay)", round, pastConsume)
		}
		if invalid != goroutines-1 {
			t.Fatalf("round %d: losers = %d, want %d", round, invalid, goroutines-1)
		}
	}
}

// seedCredential persists a credential row for the fixture's user
// with the supplied raw credential id. Returns the stored row so
// tests can mutate it before exercising the service path.
func seedCredential(t *testing.T, f *webAuthnFixture, credID []byte) *domain.WebAuthnCredential {
	t.Helper()
	id, _ := uuid.NewV7()
	cred := &domain.WebAuthnCredential{
		ID:             id,
		UserID:         f.user.ID,
		OrganizationID: f.user.OrganizationID,
		CredentialID:   credID,
		PublicKey:      []byte{0x00},
	}
	created, err := f.credRepo.Create(context.Background(), cred)
	require.NoError(t, err)
	return created
}
