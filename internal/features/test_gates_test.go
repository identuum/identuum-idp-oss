package features

import "testing"

func TestOpenGate_AllowsEverything(t *testing.T) {
	g := OpenGate{}
	for _, f := range []string{Core, AuthorizationServer, PAR, SCIM, "unknown"} {
		if !g.IsFeatureEnabled(f) {
			t.Errorf("OpenGate denied %q", f)
		}
	}
}

func TestClosedGate_DeniesEverything(t *testing.T) {
	g := ClosedGate{}
	for _, f := range []string{Core, AuthorizationServer, PAR, SCIM, ""} {
		if g.IsFeatureEnabled(f) {
			t.Errorf("ClosedGate allowed %q", f)
		}
	}
}

func TestStaticGate_AllowsListedDeniesOthers(t *testing.T) {
	g := NewStaticGate(map[string]bool{
		AuthorizationServer: true,
		PAR:                 false,
	})
	if !g.IsFeatureEnabled(AuthorizationServer) {
		t.Error("expected AuthorizationServer allowed")
	}
	if g.IsFeatureEnabled(PAR) {
		t.Error("expected PAR (set to false) denied")
	}
	if g.IsFeatureEnabled(SCIM) {
		t.Error("expected unspecified SCIM denied (default fail-closed)")
	}
}

func TestStaticGate_ZeroValueDeniesEverything(t *testing.T) {
	var g StaticGate
	for _, f := range []string{Core, AuthorizationServer, ""} {
		if g.IsFeatureEnabled(f) {
			t.Errorf("zero StaticGate allowed %q", f)
		}
	}
}

func TestStaticGate_CopyIsDefensive(t *testing.T) {
	src := map[string]bool{AuthorizationServer: true}
	g := NewStaticGate(src)
	src[AuthorizationServer] = false
	if !g.IsFeatureEnabled(AuthorizationServer) {
		t.Error("mutating source map affected gate; copy not defensive")
	}
}

func TestStaticGate_EmptyMapDeniesEverything(t *testing.T) {
	g := NewStaticGate(nil)
	if g.IsFeatureEnabled(AuthorizationServer) {
		t.Error("nil-map StaticGate should deny")
	}
}
