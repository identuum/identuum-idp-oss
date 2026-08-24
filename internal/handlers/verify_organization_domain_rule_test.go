package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// verifyDomainFakeResolver returns a controlled TXT record set (service.TXTResolver).
type verifyDomainFakeResolver struct{ records []string }

func (r verifyDomainFakeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return r.records, nil
}

// verifyDomainFakeRepo serves one pending domain row and records whether the
// row was flipped to verified (repository.OrganizationDomainRepository).
type verifyDomainFakeRepo struct {
	repository.OrganizationDomainRepository
	row      *domain.OrganizationDomain
	verified bool
}

func (r *verifyDomainFakeRepo) GetOrganizationDomainByID(context.Context, uuid.UUID) (*domain.OrganizationDomain, error) {
	return r.row, nil
}

func (r *verifyDomainFakeRepo) SetOrganizationDomainVerified(context.Context, uuid.UUID, time.Time) error {
	r.verified = true
	return nil
}

func (r *verifyDomainFakeRepo) IncrementOrganizationDomainVerificationAttempts(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

// A tenant domain is marked verified ONLY when a live DNS TXT record carries a
// token whose SHA-256 hex equals the row's stored verification-token hash: an
// absent challenge record is 400 (record-not-found) and a wrong token is 400
// (mismatch), and in neither case is the row flipped to verified; a real proof
// is 200 + verified. Driven through the ROUTED handler
// (HandleVerifyOrganizationDomain -> OrganizationDomainService.Verify ->
// DNSDomainProofVerifier.Verify) over a fake resolver + repo.
// RULE: DOMAIN-DNS-VERIFY-1
func TestVerifyOrganizationDomain_OnlyOnRealDNSProof(t *testing.T) {
	const token = "identuum-domain-verification=" + "proof-token-abc123"
	// The stored hash is sha256(raw token portion) hex.
	rawToken := "proof-token-abc123"
	sum := sha256.Sum256([]byte(rawToken))
	expected := hex.EncodeToString(sum[:])

	orgID, domainID := uuid.New(), uuid.New()
	build := func(records []string) (*gin.Engine, *verifyDomainFakeRepo) {
		exp := time.Now().Add(time.Hour)
		repo := &verifyDomainFakeRepo{row: &domain.OrganizationDomain{
			ID: domainID, OrganizationID: orgID, Domain: "example.test",
			VerificationTokenHash: &expected, VerificationTokenExpiresAt: &exp,
		}}
		verifier := service.NewDNSDomainProofVerifier(service.DNSDomainProofVerifierOptions{
			Resolver: verifyDomainFakeResolver{records: records},
		})
		svc := service.NewOrganizationDomainService(nil, repo, verifier)
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.POST("/o/:id/d/:domain_id/verify", HandleVerifyOrganizationDomain(OrganizationDomainsHandlerDeps{
			OrganizationDomainService: svc, Audit: audit.NoopService{},
		}))
		return r, repo
	}
	post := func(r *gin.Engine) int {
		req := httptest.NewRequest(http.MethodPost, "/o/"+orgID.String()+"/d/"+domainID.String()+"/verify", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// A real proof: the challenge TXT carries the token whose hash matches.
	rOK, repoOK := build([]string{token})
	if code := post(rOK); code != http.StatusOK {
		t.Fatalf("PREMISE FAILED: a valid DNS proof must verify (200), got %d", code)
	}
	if !repoOK.verified {
		t.Fatalf("a valid DNS proof must flip the row to verified")
	}

	// No challenge record at all -> 400, NOT verified.
	rNone, repoNone := build([]string{"some-unrelated-txt"})
	if code := post(rNone); code != http.StatusBadRequest {
		t.Errorf("an absent challenge record must be 400 (not verified), got %d", code)
	}
	if repoNone.verified {
		t.Errorf("a domain with no DNS challenge record must NEVER be marked verified")
	}

	// A challenge record with the WRONG token -> 400 mismatch, NOT verified.
	rWrong, repoWrong := build([]string{"identuum-domain-verification=" + "the-wrong-token"})
	if code := post(rWrong); code != http.StatusBadRequest {
		t.Errorf("a wrong-token challenge record must be 400 (mismatch), got %d", code)
	}
	if repoWrong.verified {
		t.Errorf("a domain whose TXT token does not hash to the expected proof must NEVER be verified")
	}

	// Direct exercise of the DNS proof verifier (exact reach): a TXT record whose
	// token hashes to the expected value proves control; an absent record does not.
	dvOK := service.NewDNSDomainProofVerifier(service.DNSDomainProofVerifierOptions{
		Resolver: verifyDomainFakeResolver{records: []string{token}},
	})
	if err := dvOK.Verify(context.Background(), "example.test", expected); err != nil {
		t.Errorf("the DNS verifier must accept a matching TXT proof, got %v", err)
	}
	dvNone := service.NewDNSDomainProofVerifier(service.DNSDomainProofVerifierOptions{
		Resolver: verifyDomainFakeResolver{records: []string{"unrelated"}},
	})
	if err := dvNone.Verify(context.Background(), "example.test", expected); err == nil {
		t.Errorf("the DNS verifier must reject a domain with no challenge TXT record")
	}
}
