package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// D-020: the lockout/risk counters key an IPv6 client by its /64, so an
// attacker rotating addresses inside one /64 is counted as one source.

func TestLoginRisk_IPv6SprayRotatedInsideA64TripsTheIPCounter(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 1000, Window: time.Minute})
	// 10 distinct accounts, each from a different address in 2001:db8:aa:bb::/64.
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("2001:db8:aa:bb::%x", i+1)
		_ = svc.Record(context.Background(), fmt.Sprintf("user%d@example.com", i), ip, LoginRiskPurposePassword, false)
	}
	if err := svc.Check(context.Background(), "next@example.com", "2001:db8:aa:bb::ff", LoginRiskPurposePassword); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("a spray rotated inside one /64 escaped the IP counter: %v", err)
	}
	// Another /64 is another source.
	if err := svc.Check(context.Background(), "next@example.com", "2001:db8:aa:bc::1", LoginRiskPurposePassword); err != nil {
		t.Fatalf("a different /64 was locked: %v", err)
	}
}

func TestLoginRisk_IPv6AccountGuessRotatedInsideA64TripsTheAccountCounter(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 3, Window: time.Minute})
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("2001:db8:aa:bb::%x", i+1)
		_ = svc.Record(context.Background(), "victim@example.com", ip, LoginRiskPurposePassword, false)
	}
	if err := svc.Check(context.Background(), "victim@example.com", "2001:db8:aa:bb::9", LoginRiskPurposePassword); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("guesses rotated inside one /64 escaped the account counter: %v", err)
	}
}

func TestLoginRisk_IPv4KeysUnchanged(t *testing.T) {
	repo := newLoginAttemptRepo()
	svc := NewLoginRiskService(nil, repo, LoginRiskServiceOptions{Threshold: 3, Window: time.Minute})
	for i := 0; i < 3; i++ {
		_ = svc.Record(context.Background(), "victim@example.com", fmt.Sprintf("198.51.100.%d", i+1), LoginRiskPurposePassword, false)
	}
	// Each IPv4 address is its own source: no single (email, ip) pair reached 3.
	if err := svc.Check(context.Background(), "victim@example.com", "198.51.100.9", LoginRiskPurposePassword); err != nil {
		t.Fatalf("IPv4 addresses were grouped: %v", err)
	}
}
