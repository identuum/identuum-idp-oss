//go:build integration

package postgres_test

// OSS-G8-BN2 against the live schema: client_binding is a 32-byte value on the
// passkey proof kind and NULL on every other kind. A malformed binding is
// refused on either side.

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestMFAPending_ClientBindingOnlyOnThePasskeyProofKind(t *testing.T) {
	pool := keyEncPool(t)
	t.Cleanup(pool.Close) // registered first, so it runs after the row cleanup below
	ctx := context.Background()
	orgID := seedScratchOrg(t, pool)
	userID := seedSessionUser(t, ctx, pool, orgID)
	var ids []uuid.UUID
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mfa_pending_login_sessions WHERE id = ANY($1)`, ids)
	})
	insert := func(kind string, binding []byte) error {
		id := uuid.New()
		ids = append(ids, id)
		_, err := pool.Exec(ctx, `
			INSERT INTO mfa_pending_login_sessions (id, user_id, kind, remember_me, expires_at, client_binding)
			VALUES ($1, $2, $3, false, $4, $5)`, id, userID, kind, time.Now().UTC().Add(time.Hour), binding)
		return err
	}
	full := bytes.Repeat([]byte{1}, 32)
	short := bytes.Repeat([]byte{1}, 16)
	type bindingCase struct {
		kind    string
		binding []byte
		ok      bool
	}
	cases := []bindingCase{
		{"password_change_passkey_uv", full, true},
		{"password_change_passkey_uv", nil, false},
		{"password_change_passkey_uv", short, false},
		{"password_change_passkey_uv", []byte{}, false},
	}
	for _, kind := range []string{"enroll", "verify", "password_change"} {
		cases = append(cases,
			bindingCase{kind, nil, true},
			bindingCase{kind, full, false},
			bindingCase{kind, short, false},
			bindingCase{kind, []byte{}, false},
		)
	}
	for _, c := range cases {
		err := insert(c.kind, c.binding)
		if c.ok {
			if err != nil {
				t.Errorf("kind %s, binding of %d bytes (nil=%v): err=%v; want accepted", c.kind, len(c.binding), c.binding == nil, err)
			}
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "mfa_pending_login_sessions_client_binding_check" {
			t.Errorf("kind %s, binding of %d bytes (nil=%v): err=%v; want the client_binding check to refuse it", c.kind, len(c.binding), c.binding == nil, err)
		}
	}
}
