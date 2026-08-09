package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// OpaqueMinter is the reference opaque-token AccessTokenMinter: it ignores
// the claim VALUES (an opaque token embeds nothing) and returns a fresh
// 256-bit random token, base64url-encoded (no padding), whose storeKey is
// the SHA-256 hex digest of the wire token. It exists both as the CE-shaped
// second implementation that keeps the AccessTokenMinter seam honest (a real
// format alternative, not a hollow relabel) and as a self-contained,
// domain-free reference the overlay can build on.
//
// SECURITY: the wire token is a bearer credential — callers persist only the
// storeKey (the hash) and MUST NOT log the wire token. The hash-as-storeKey
// mirrors how the OSS token stores index access tokens by digest.
type OpaqueMinter struct{}

// NewOpaqueMinter constructs an OpaqueMinter. It holds no state; the zero
// value is equally usable.
func NewOpaqueMinter() *OpaqueMinter { return &OpaqueMinter{} }

// opaqueTokenBytes is the entropy width of an opaque token: 256 bits.
const opaqueTokenBytes = 32

// Mint returns a random opaque token and its SHA-256 hex storeKey. The
// supplied claims are intentionally unused — an opaque token carries no
// embedded claims; a real deployment persists the claims out-of-band keyed
// by storeKey.
func (m *OpaqueMinter) Mint(_ context.Context, _ TokenClaims) (wireToken string, storeKey string, err error) {
	var buf [opaqueTokenBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", "", err
	}
	wire := base64.RawURLEncoding.EncodeToString(buf[:])
	sum := sha256.Sum256([]byte(wire))
	return wire, hex.EncodeToString(sum[:]), nil
}
