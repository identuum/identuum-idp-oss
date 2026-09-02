package handlers

// address_phone_userinfo_test.go — THE-ADDRESS-PHONE-CLAIMS at userinfo:
// scope=address releases the structured address (set members only),
// scope=phone releases phone_number + phone_number_verified=false; the
// claims parameter releases claim-by-claim; without scope or claim nothing
// personal lands; a service account never gets them.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestUserinfo_AddressAndPhoneScopes(t *testing.T) {
	uid := uuid.New()
	phone, locality, country := "+442079460000", "London", "United Kingdom"
	profile := &domain.UserProfile{UserID: uid, PhoneNumber: &phone, AddressLocality: &locality, AddressCountry: &country, UpdatedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)}
	serve := func(t *testing.T, scope string, userinfoClaims []string, actorType string) map[string]any {
		t.Helper()
		v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
			Sub: uid.String(), UserID: uid, Email: "user@example.com", Scope: scope, UserInfoClaims: userinfoClaims, ActorType: actorType,
		}}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
			IntrospectionService: service.NewIntrospectionService(nil, v, nil),
			UserLookup:           &fakeUserinfoUserLookup{user: &domain.User{ID: uid, Name: userinfoStrPtr("Alice Example")}},
			ProfileLookup:        fakeProfileLookup{p: profile},
		})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
		req.Header.Set("Authorization", "Bearer ANY")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d body=%q", w.Code, w.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body
	}

	body := serve(t, "openid address phone", nil, "")
	addr, ok := body["address"].(map[string]any)
	if !ok || addr["locality"] != "London" || addr["country"] != "United Kingdom" || len(addr) != 2 {
		t.Errorf("address scope must release exactly the set members: %v", body["address"])
	}
	if body["phone_number"] != "+442079460000" || body["phone_number_verified"] != false {
		t.Errorf("phone scope must release phone_number + phone_number_verified=false: %v", body)
	}
	for _, k := range []string{"name", "email", "given_name"} {
		if v, present := body[k]; present {
			t.Errorf("%s released without its scope: %v", k, v)
		}
	}

	body = serve(t, "openid address", nil, "")
	if body["address"] == nil || body["phone_number"] != nil || body["phone_number_verified"] != nil {
		t.Errorf("address scope alone: %v", body)
	}
	body = serve(t, "openid phone", nil, "")
	if body["address"] != nil || body["phone_number"] == nil {
		t.Errorf("phone scope alone: %v", body)
	}

	// Claims parameter: only the requested claim.
	body = serve(t, "openid", []string{"phone_number"}, "")
	if body["phone_number"] != "+442079460000" || body["phone_number_verified"] != false || body["address"] != nil {
		t.Errorf("claims parameter phone_number: %v", body)
	}
	body = serve(t, "openid", []string{"address"}, "")
	if body["address"] == nil || body["phone_number"] != nil {
		t.Errorf("claims parameter address: %v", body)
	}

	// Neither → nothing personal.
	body = serve(t, "openid", nil, "")
	for _, k := range []string{"address", "phone_number", "phone_number_verified"} {
		if v, present := body[k]; present {
			t.Errorf("%s released without scope or claim: %v", k, v)
		}
	}

	// A service account carries no postal address or phone.
	body = serve(t, "openid address phone", nil, service.ActorTypeServiceAccount)
	for _, k := range []string{"address", "phone_number", "phone_number_verified"} {
		if v, present := body[k]; present {
			t.Errorf("service account: %s released: %v", k, v)
		}
	}
}
