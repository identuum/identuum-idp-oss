package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/extensionmint"
	"github.com/identuum/identuum-idp-oss/pkg/extension"
)

// WithRestrictions adds extension restrictions to the API resource writes
// (OSS-SEAM-4). They run after the actor, tenant and input checks and before
// any write; nil or empty keeps OSS as it is.
func (s *APIResourceService) WithRestrictions(rs []extension.Restriction) *APIResourceService {
	s.restrictions = append([]extension.Restriction(nil), rs...)
	return s
}

// restrict builds the Decision for one write and runs every restriction on
// it. With no restrictions it does nothing.
func (s *APIResourceService) restrict(ctx context.Context, actor *domain.Principal, op string, target uuid.UUID) error {
	if len(s.restrictions) == 0 {
		return nil
	}
	actorID := actor.Sub
	if actor.UserID != uuid.Nil {
		actorID = actor.UserID.String()
	}
	d, _ := extensionmint.NewDecision(extensionmint.Fields{
		Actor: actorID, Tenant: actor.OrganizationID.String(), Operation: op, Target: target.String(),
	}).(extension.Decision)
	return checkRestrictions(ctx, s.restrictions, d)
}

// checkRestrictions is the deny-only dispatcher: a zero Decision, a nil
// restriction, a refusal, an error and a panic are all denials, answered with
// a stable code (owner ruling aa).
func checkRestrictions(ctx context.Context, rs []extension.Restriction, d extension.Decision) error {
	if d.IsZero() {
		return &extension.Denial{Code: extension.Restricted}
	}
	for _, r := range rs {
		if err := checkRestriction(ctx, r, d); err != nil {
			return err
		}
	}
	return nil
}

func checkRestriction(ctx context.Context, r extension.Restriction, d extension.Decision) (err error) {
	defer func() {
		if recover() != nil {
			err = &extension.Denial{Code: extension.Restricted}
		}
	}()
	if r == nil {
		return &extension.Denial{Code: extension.Restricted}
	}
	refusal := r.Check(ctx, d)
	if refusal == nil {
		return nil
	}
	var denial *extension.Denial
	if errors.As(refusal, &denial) && denial != nil {
		switch denial.Code {
		case extension.LicenseRequired, extension.QuotaExceeded:
			return &extension.Denial{Code: denial.Code}
		}
	}
	return &extension.Denial{Code: extension.Restricted}
}
