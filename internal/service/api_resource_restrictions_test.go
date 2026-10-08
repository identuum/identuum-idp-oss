package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/extensionmint"
	"github.com/identuum/identuum-idp-oss/pkg/extension"
)

type restrictionFunc func(context.Context, extension.Decision) error

func (f restrictionFunc) Check(ctx context.Context, d extension.Decision) error { return f(ctx, d) }

// OSS-SEAM-4 proofs 3 and 5 at the dispatcher: a zero Decision is refused
// before any restriction runs; a refusal keeps its stable code; an error, an
// unknown code, a nil restriction and a panic are all 403 restricted.
func TestCheckRestrictions(t *testing.T) {
	ctx := context.Background()
	d := extensionmint.NewDecision(extensionmint.Fields{Actor: "u", Tenant: "t", Operation: extension.OperationAPIResourceCreate, Target: "x"}).(extension.Decision)
	called := 0
	allow := restrictionFunc(func(context.Context, extension.Decision) error { called++; return nil })

	if err := checkRestrictions(ctx, []extension.Restriction{allow}, extension.Decision{}); !isDenial(err, extension.Restricted) || called != 0 {
		t.Fatalf("a zero Decision: %v after %d call(s); want restricted before any restriction runs", err, called)
	}
	if err := checkRestrictions(ctx, []extension.Restriction{allow}, d); err != nil || called != 1 {
		t.Fatalf("an allowing restriction: %v after %d call(s); want nil after one", err, called)
	}
	cases := []struct {
		name string
		r    extension.Restriction
		want extension.Code
	}{
		{"license_required", restrictionFunc(func(context.Context, extension.Decision) error {
			return &extension.Denial{Code: extension.LicenseRequired}
		}), extension.LicenseRequired},
		{"quota_exceeded, wrapped", restrictionFunc(func(context.Context, extension.Decision) error {
			return fmt.Errorf("ceiling: %w", &extension.Denial{Code: extension.QuotaExceeded})
		}), extension.QuotaExceeded},
		{"an unknown code", restrictionFunc(func(context.Context, extension.Decision) error {
			return &extension.Denial{Code: "allow"}
		}), extension.Restricted},
		{"an error", restrictionFunc(func(context.Context, extension.Decision) error { return errors.New("store down") }), extension.Restricted},
		{"a panic", restrictionFunc(func(context.Context, extension.Decision) error { panic("boom") }), extension.Restricted},
		{"a nil restriction", nil, extension.Restricted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			after := 0
			last := restrictionFunc(func(context.Context, extension.Decision) error { after++; return nil })
			err := checkRestrictions(ctx, []extension.Restriction{tc.r, last}, d)
			if !isDenial(err, tc.want) || after != 0 {
				t.Fatalf("got %v, %d later call(s); want a %s denial and no later restriction run", err, after, tc.want)
			}
		})
	}
}

func isDenial(err error, code extension.Code) bool {
	var d *extension.Denial
	return errors.As(err, &d) && d.Code == code
}
