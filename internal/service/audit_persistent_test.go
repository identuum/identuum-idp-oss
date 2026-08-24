package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// captureInserter records the last domain.AuditEvent handed to Insert.
type captureInserter struct {
	last  *domain.AuditEvent
	calls int
	err   error
}

func (c *captureInserter) Insert(_ context.Context, e domain.AuditEvent) error {
	c.calls++
	ev := e
	c.last = &ev
	return c.err
}

// L-2 mapping: uuid.Nil -> NULL (*uuid.UUID nil), "" -> NULL (*string nil),
// non-zero values preserved, metadata passed through untouched, actor_type +
// priority are non-null value columns, and a UUIDv7 id is minted.
func TestPersistentAuditService_MapsZeroValuesToNull(t *testing.T) {
	ins := &captureInserter{}
	svc := NewPersistentAuditService(ins)

	if err := svc.Record(context.Background(), audit.Event{
		Action:    "user.login.success",
		ActorType: "user",
		// ActorID / OrganizationID / SubjectID left zero -> NULL
		// ActorEmail / etc left "" -> NULL
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := ins.last
	if got == nil {
		t.Fatal("Insert was not called")
	}
	if got.EventType != domain.AuditEventType("user.login.success") {
		t.Fatalf("event_type = %q", got.EventType)
	}
	if got.ActorType != "user" {
		t.Fatalf("actor_type = %q, want the value 'user' (non-null column)", got.ActorType)
	}
	if got.Priority != domain.AuditPriorityNormal {
		t.Fatalf("priority = %q, want normal default", got.Priority)
	}
	if got.ID == uuid.Nil {
		t.Fatal("id must be minted, got Nil")
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("created_at must be set (zero timestamp -> now())")
	}
	for name, p := range map[string]any{
		"actor_id":              got.ActorID,
		"actor_organization_id": got.ActorOrganizationID,
		"subject_id":            got.SubjectID,
		"actor_email":           got.ActorEmail,
		"actor_role":            got.ActorRole,
		"subject_type":          got.SubjectType,
		"subject_email":         got.SubjectEmail,
		"ip_address":            got.IPAddress,
		"user_agent":            got.UserAgent,
		"request_id":            got.RequestID,
		"correlation_id":        got.CorrelationID,
	} {
		if !isNilPtr(p) {
			t.Fatalf("%s must be nil (NULL) for a zero input, got %v", name, p)
		}
	}
}

// Non-zero values map through to non-nil pointers; metadata is the same map.
// RULE: AUDIT-PERSIST-1
func TestPersistentAuditService_PreservesValuesAndMetadata(t *testing.T) {
	ins := &captureInserter{}
	svc := NewPersistentAuditService(ins)

	actor := uuid.New()
	org := uuid.New()
	subj := uuid.New()
	ts := time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC)
	md := map[string]any{"reason": "test", "count": 3}

	if err := svc.Record(context.Background(), audit.Event{
		Action:         "org.created",
		ActorType:      "site_admin",
		ActorID:        actor,
		ActorEmail:     "admin@system.local",
		ActorRole:      "site_admin",
		OrganizationID: org,
		SubjectID:      subj,
		SubjectType:    "organization",
		SubjectEmail:   "owner@tenant.invalid",
		IPAddress:      "203.0.113.9",
		UserAgent:      "curl/8",
		RequestID:      "req-1",
		CorrelationID:  "corr-1",
		Timestamp:      ts,
		Metadata:       md,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := ins.last
	if *got.ActorID != actor || *got.ActorOrganizationID != org || *got.SubjectID != subj {
		t.Fatal("uuid fields not preserved")
	}
	if *got.ActorEmail != "admin@system.local" || *got.SubjectEmail != "owner@tenant.invalid" {
		t.Fatal("email fields not preserved")
	}
	if *got.IPAddress != "203.0.113.9" || *got.CorrelationID != "corr-1" || *got.RequestID != "req-1" {
		t.Fatal("string fields not preserved")
	}
	if !got.CreatedAt.Equal(ts) {
		t.Fatalf("created_at = %v, want the supplied timestamp (clock-source preserved)", got.CreatedAt)
	}
	// Metadata round-trip: same content, untouched (no injected fields).
	if len(got.Metadata) != 2 || got.Metadata["reason"] != "test" || got.Metadata["count"] != 3 {
		t.Fatalf("metadata mutated: %v", got.Metadata)
	}
}

// The Service contract is best-effort: a repo error is returned as a hint but
// the mapping still ran once.
func TestPersistentAuditService_ReturnsInserterError(t *testing.T) {
	ins := &captureInserter{err: errors.New("db down")}
	svc := NewPersistentAuditService(ins)
	if err := svc.Record(context.Background(), audit.Event{Action: "x", ActorType: "system"}); err == nil {
		t.Fatal("want the inserter error surfaced")
	}
	if ins.calls != 1 {
		t.Fatalf("Insert calls = %d, want 1", ins.calls)
	}
}

func isNilPtr(p any) bool {
	switch v := p.(type) {
	case *uuid.UUID:
		return v == nil
	case *string:
		return v == nil
	default:
		return false
	}
}

// Outcome maps: "" -> NULL, a value round-trips (L-2 follow-up).
func TestPersistentAuditService_OutcomeMapping(t *testing.T) {
	ins := &captureInserter{}
	svc := NewPersistentAuditService(ins)

	// empty -> NULL
	if err := svc.Record(context.Background(), audit.Event{Action: "x", ActorType: "system"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if ins.last.Outcome != nil {
		t.Fatalf("empty outcome must map to NULL, got %v", ins.last.Outcome)
	}

	// value -> preserved
	if err := svc.Record(context.Background(), audit.Event{Action: "x", ActorType: "system", Outcome: "denied"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if ins.last.Outcome == nil || *ins.last.Outcome != "denied" {
		t.Fatalf("outcome value not preserved: %v", ins.last.Outcome)
	}
}

// Regression for the L-2 defect fixed here: internal/handlers/auth_mfa_enroll.go
// emits the SAME Action ("auditAction") twice, differing ONLY by Outcome
// "success" vs "denied" (backchannel_deliveries.go does the same with
// "delivery_failed"). Before outcome was persisted, a DENIED MFA step-up and a
// SUCCESSFUL one produced byte-identical rows. This pins that a same-Action /
// different-Outcome pair now maps to rows that DIFFER.
func TestPersistentAuditService_SameActionDifferentOutcomeDiffers(t *testing.T) {
	ins := &captureInserter{}
	svc := NewPersistentAuditService(ins)

	const action = "mfa.stepup" // stands in for auth_mfa_enroll's shared auditAction
	if err := svc.Record(context.Background(), audit.Event{Action: action, ActorType: "user", Outcome: "success"}); err != nil {
		t.Fatalf("Record success: %v", err)
	}
	success := *ins.last
	if err := svc.Record(context.Background(), audit.Event{Action: action, ActorType: "user", Outcome: "denied"}); err != nil {
		t.Fatalf("Record denied: %v", err)
	}
	denied := *ins.last

	if success.EventType != denied.EventType {
		t.Fatalf("test setup: event_type should be identical, got %q vs %q", success.EventType, denied.EventType)
	}
	if success.Outcome == nil || denied.Outcome == nil || *success.Outcome == *denied.Outcome {
		t.Fatalf("same Action, different Outcome must produce DIFFERENT rows — outcome is the discriminator (got success=%v denied=%v)", success.Outcome, denied.Outcome)
	}
}
