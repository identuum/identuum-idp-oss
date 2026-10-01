//go:build integration

// D-020: over IPv6 nothing degrades — an audit event recorded from an IPv6
// client keeps that address in audit_events.ip_address (INET), as an IPv4
// one does. Rows are tagged per run and removed on exit.
package e2e

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_AuditEvents_IPv6Address(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()
	tag := "e2e.v6." + uuid.NewString()[:8] + "."
	defer func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM audit_events WHERE event_type LIKE $1", tag+"%")
	}()

	svc := service.NewPersistentAuditService(postgres.NewPgxRepositories(pool, e2eSigningKeyCipher()).Audit)
	for _, ip := range []string{"2001:db8:aa:bb::1234", "::1", "203.0.113.4"} {
		et := tag + "login.success." + ip
		if err := svc.Record(ctx, audit.Event{Action: et, ActorType: "user", ActorID: uuid.New(), IPAddress: ip, Outcome: "success"}); err != nil {
			t.Fatalf("Record from %s: %v", ip, err)
		}
		var got string
		if err := pool.QueryRow(ctx, "SELECT host(ip_address) FROM audit_events WHERE event_type = $1", et).Scan(&got); err != nil {
			t.Fatalf("read back %s: %v", ip, err)
		}
		if got != ip {
			t.Errorf("audit ip_address = %q, want %q", got, ip)
		}
	}
}
