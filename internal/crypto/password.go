package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"golang.org/x/crypto/argon2"
)

var (
	ErrUnsupportedHashFormat     = errors.New("unsupported password hash format")
	ErrInvalidHashFormat         = errors.New("invalid password hash format")
	ErrMismatchedHashAndPassword = errors.New("hashedPassword is not the hash of the given password")
)

// GenerateHash generates an Argon2id hash from a password using domain constraints.
// It returns the hash serialized in the standard PHC string format.
func GenerateHash(password []byte) (string, error) {
	salt := make([]byte, domain.Argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(password, salt, domain.Argon2Time, domain.Argon2Memory, domain.Argon2Threads, domain.Argon2KeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, domain.Argon2Memory, domain.Argon2Time, domain.Argon2Threads, b64Salt, b64Hash), nil
}

// CompareHashAndPassword compares a PHC-formatted argon2id hash with a password.
// Returns ErrMismatchedHashAndPassword on a valid-format mismatch so callers can
// distinguish "wrong password" from malformed-hash errors.
func CompareHashAndPassword(encodedHash []byte, password []byte) error {
	hashStr := string(encodedHash)

	// Only argon2id is supported.
	if !strings.HasPrefix(hashStr, "$argon2id$") {
		return ErrUnsupportedHashFormat
	}

	// Parse PHC format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	parts := strings.Split(hashStr, "$")
	if len(parts) != 6 {
		return ErrInvalidHashFormat
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return ErrInvalidHashFormat
	}

	var memory, time uint32
	var threads uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return ErrInvalidHashFormat
	}

	// P3-6: BOUND THE COST BEFORE PAYING IT.
	//
	// These three numbers come out of the STORED hash and used to go straight
	// into argon2.IDKey, which means whoever can write a password_hash row
	// chooses how much memory and CPU this process spends on every subsequent
	// login attempt for that user. m= is a uint32, so the ceiling was 4 TiB per
	// attempt. That is not a theoretical bound: a hostile PHC string of
	// `m=4294967295,t=4294967295,p=255` hangs the verifier outright —
	// TestVerifyPassword_RejectsAbsurdArgon2Parameters times out at 45s against
	// the unbounded version, and the cost is paid BEFORE the hash comparison
	// fails, so an invalid hash is just as expensive as a valid one.
	//
	// The ceilings are the values GenerateHash actually emits, with headroom for
	// a deliberate future increase: 16x memory, 10x iterations, 4x threads. A
	// legitimately-produced hash is far under all three; nothing that verifies
	// today stops verifying. A row above them is corrupt or hostile and is
	// refused as a MALFORMED HASH, never as a wrong password, so the two stay
	// distinguishable in logs and metrics.
	const (
		maxArgon2Memory  = domain.Argon2Memory * 16
		maxArgon2Time    = domain.Argon2Time * 10
		maxArgon2Threads = domain.Argon2Threads * 4
	)
	if memory == 0 || memory > maxArgon2Memory ||
		time == 0 || time > maxArgon2Time ||
		threads == 0 || threads > maxArgon2Threads {
		return ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidHashFormat
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidHashFormat
	}
	if len(decodedHash) == 0 || len(decodedHash) > int(^uint32(0)>>1) {
		return ErrInvalidHashFormat
	}
	keyLen := uint32(len(decodedHash)) //nolint:gosec // G115: bounds checked above

	computedHash := argon2.IDKey(password, salt, time, memory, threads, keyLen)

	if subtle.ConstantTimeCompare(decodedHash, computedHash) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}
