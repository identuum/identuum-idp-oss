package handlers

import (
	"context"
	"net/http"
	"testing"
)

// A registration access token authorizes RFC 7592 management only while it
// is the client's live token: a wrong or rotated-away token gets the one
// opaque 401, and after revocation the client disappears from the
// management surface entirely — 404, not 401, so revoked DCR clients are
// not enumerable. Driven through the real routed handlers (the public
// path), not the service in isolation.
// RULE: DCR-RAT-LIFECYCLE-1
func TestRFC7592_RATLifecycleAuthorizesOnlyLiveToken(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	clientID, rat := registerDCRClient(t, eng)
	path := "/api/v1/oauth/register/" + clientID.String()
	ctx := context.Background()

	// PREMISE: the live token authorizes.
	if rec := dcrMgmtJSON(t, eng, http.MethodGet, path, nil, rat); rec.Code != http.StatusOK {
		t.Fatalf("PREMISE FAILED: the live RAT must authorize management GET, got %d body=%q", rec.Code, rec.Body.String())
	}

	// A wrong token is refused with the opaque 401.
	if rec := dcrMgmtJSON(t, eng, http.MethodGet, path, nil, "not-the-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a wrong registration access token must be refused with the opaque 401, got %d body=%q", rec.Code, rec.Body.String())
	}

	// Rotation invalidates the prior token immediately.
	newRAT, err := eng.ratSvc.Mint(ctx, clientID)
	if err != nil {
		t.Fatalf("rotate RAT: %v", err)
	}
	if rec := dcrMgmtJSON(t, eng, http.MethodGet, path, nil, rat); rec.Code != http.StatusUnauthorized {
		t.Errorf("a rotated-away registration access token must be refused with the opaque 401, got %d body=%q", rec.Code, rec.Body.String())
	}
	if rec := dcrMgmtJSON(t, eng, http.MethodGet, path, nil, newRAT); rec.Code != http.StatusOK {
		t.Fatalf("the rotated-in RAT must authorize, got %d body=%q", rec.Code, rec.Body.String())
	}

	// Revocation removes the row: the client vanishes from the RFC 7592
	// surface — 404, never 401, so revoked DCR clients are not enumerable.
	if err := eng.ratSvc.Revoke(ctx, clientID); err != nil {
		t.Fatalf("revoke RAT: %v", err)
	}
	if rec := dcrMgmtJSON(t, eng, http.MethodGet, path, nil, newRAT); rec.Code != http.StatusNotFound {
		t.Errorf("after revocation the client must disappear from the management surface (404, not 401): got %d body=%q", rec.Code, rec.Body.String())
	}
}
