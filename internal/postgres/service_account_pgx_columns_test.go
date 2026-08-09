package postgres

import (
	"os"
	"strings"
	"testing"
)

// TestServiceAccountPgxOmitsSPIFFEColumns is a drift guard: after the
// open-core SPIFFE column cleanup, the OSS pgx repository must not
// reference origin_peer_id or origin_spiffe_id anywhere in its SQL or
// scan-destination code. The schema lives in CE; the OSS repository is
// blind to it. If a future slice accidentally re-introduces these
// references, this test surfaces it immediately.
func TestServiceAccountPgxOmitsSPIFFEColumns(t *testing.T) {
	data, err := os.ReadFile("service_account_repository_pgx.go")
	if err != nil {
		t.Fatalf("read service_account_repository_pgx.go: %v", err)
	}
	body := string(data)

	banned := []string{
		"origin_peer_id",
		"origin_spiffe_id",
		"OriginPeerID",
		"OriginSPIFFEID",
	}
	for _, b := range banned {
		if strings.Contains(body, b) {
			t.Errorf("OSS service_account_repository_pgx.go must not reference %q; "+
				"SPIFFE-origin columns belong to the CE overlay", b)
		}
	}
}
