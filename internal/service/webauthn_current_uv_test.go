package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// F1 (SEC-MFA-REVIEW-2026-10-08; V7-117, V7-266): FinishLogin reported the
// credential's stored, historical verification flag — always true — as the
// user verification of THIS assertion, so a presence-only passkey satisfied
// required MFA. Across the real go-webauthn validator, a correctly signed
// assertion with UV clear must report false, and one with UV set true.
func TestFinishLogin_ReportsTheUVOfThisAssertion(t *testing.T) {
	const rpID, origin = "idp.test", "https://idp.test"
	for _, tc := range []struct {
		name  string
		flags byte
		want  bool
	}{
		{"user presence only", 0x01, false},
		{"user presence and verification", 0x01 | 0x04, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			point, err := priv.PublicKey.Bytes() // 0x04 || X || Y
			if err != nil {
				t.Fatal(err)
			}
			cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
				PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
				Curve:         int64(webauthncose.P256), XCoord: point[1:33], YCoord: point[33:65],
			})
			if err != nil {
				t.Fatal(err)
			}
			uid, _ := uuid.NewV7()
			user := &domain.User{ID: uid, Email: "uv@example.test", Role: domain.RoleOrgUser, OrganizationID: uuid.New()}
			credRepo := newMemCredRepo()
			credID := []byte("uv-test-credential")
			if _, err := credRepo.Create(context.Background(), &domain.WebAuthnCredential{
				ID: uuid.New(), UserID: uid, OrganizationID: user.OrganizationID, CredentialID: credID, PublicKey: cose,
			}); err != nil {
				t.Fatal(err)
			}
			svc, err := NewWebAuthnService(WebAuthnServiceConfig{
				BaseURL: origin, RPDisplayName: "test", UserRepo: newMemUserRepoForWebAuthn(user), CredRepo: credRepo,
				SessionRepo: repository.NewInMemoryWebAuthnSessionRepository(), Audit: audit.NoopService{}, Logger: zap.NewNop(),
			})
			if err != nil {
				t.Fatal(err)
			}
			assertion, sessionID, err := svc.BeginLogin(context.Background(), user)
			if err != nil {
				t.Fatal(err)
			}
			b64 := base64.RawURLEncoding.EncodeToString
			clientData, _ := json.Marshal(map[string]any{
				"type": "webauthn.get", "challenge": assertion.Response.Challenge.String(), "origin": origin, "crossOrigin": false,
			})
			rpHash := sha256.Sum256([]byte(rpID))
			authData := append(append(rpHash[:], tc.flags), binary.BigEndian.AppendUint32(nil, 1)...)
			cdHash := sha256.Sum256(clientData)
			digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
			sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(map[string]any{
				"id": b64(credID), "rawId": b64(credID), "type": "public-key",
				"response": map[string]string{
					"clientDataJSON": b64(clientData), "authenticatorData": b64(authData),
					"signature": b64(sig), "userHandle": b64(uid[:]),
				},
			})
			req := httptest.NewRequest(http.MethodPost, origin+"/api/v1/webauthn/login/finish", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			_, _, userVerified, err := svc.FinishLogin(context.Background(), sessionID, req)
			if err != nil {
				t.Fatalf("a correctly signed assertion was refused: %v", err)
			}
			if userVerified != tc.want {
				t.Fatalf("FinishLogin reported user verification %v for an assertion whose UV bit is %v", userVerified, tc.want)
			}
		})
	}
}
