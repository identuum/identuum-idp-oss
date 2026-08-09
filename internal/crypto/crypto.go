package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// CryptoService performs AES-GCM encryption and decryption for all at-rest
// secrets the service holds (MFA seeds, OIDC state, identity-provider
// configs, agent tokens, webhook signing secrets, etc.).
//
// The service holds one active key used for every new Encrypt, plus an
// unordered pool of previous keys retained so ciphertexts produced before
// a rotation continue to decrypt. Callers never see the key id — they
// call Encrypt/Decrypt with opaque strings.
//
// Ciphertext formats (newest first):
//
//	v2:<keyID>:<b64(nonce||ciphertext)>   — current format, keyed
//	v1:<b64(nonce||ciphertext)>           — legacy keyed, no id
//	<b64(nonce||ciphertext)>              — pre-v1 legacy, StdEncoding
//
// v1: and legacy ciphertexts carry no key identifier. Decrypt tries the
// active key first, then every previous key; callers that fail here must
// surface the failure — there is no other fallback.
type CryptoService struct {
	mu       sync.RWMutex
	active   keyEntry
	previous map[string]keyEntry // keyID → entry
}

// keyEntry is one loaded key slot. id is derived deterministically from
// the material so two processes booted from the same Vault secret agree
// on the id without coordinating.
type keyEntry struct {
	id       string // 16-char lower-hex prefix of sha256(material)
	material []byte // 32-byte AES-256 key
}

// NewCryptoService creates a service with a single active key. No previous
// keys are registered — SwapActive is the only way to install a previous.
func NewCryptoService(hexKey string) (*CryptoService, error) {
	entry, err := parseKeyEntry(hexKey)
	if err != nil {
		return nil, err
	}
	return &CryptoService{
		active:   entry,
		previous: make(map[string]keyEntry),
	}, nil
}

// parseKeyEntry decodes a hex-encoded 32-byte key and attaches its id.
// Extracted so SwapActive and NewCryptoService share the same validation.
func parseKeyEntry(hexKey string) (keyEntry, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return keyEntry{}, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return keyEntry{}, fmt.Errorf("key must be 32 bytes (got %d)", len(key))
	}
	return keyEntry{id: deriveKeyID(key), material: key}, nil
}

// deriveKeyID returns the stable 16-char hex identifier for raw key bytes.
// Using a SHA-256 prefix keeps the id short enough to prefix every
// ciphertext without bloat while remaining collision-resistant for any
// realistic fleet size.
func deriveKeyID(keyBytes []byte) string {
	sum := sha256.Sum256(keyBytes)
	return hex.EncodeToString(sum[:8])
}

// Key returns a copy of the currently active key material. Callers use
// this to derive subkeys (e.g. HMAC for audit PII pseudonymisation).
// After a rotation, subsequent callers see the new material — old
// subkey-derived values do NOT migrate automatically.
func (s *CryptoService) Key() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]byte, len(s.active.material))
	copy(cp, s.active.material)
	return cp
}

// ActiveKeyID returns the current active key's id. Safe to log; the id is
// not the key material.
func (s *CryptoService) ActiveKeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.id
}

// PreviousKeyIDs returns the ids of every previous key still held in the
// decrypt pool. Useful for metrics (crypto_previous_keys_total) and for
// ops checks before a key-retirement sweep.
func (s *CryptoService) PreviousKeyIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.previous))
	for id := range s.previous {
		ids = append(ids, id)
	}
	return ids
}

// SwapActive promotes the current active key to the previous-keys pool
// and installs the supplied hex key as the new active. A no-op if the
// supplied key matches the current active (same id) — this is the common
// case when the watcher polls an unchanged Vault secret.
//
// Returns the old and new key ids plus whether a swap actually occurred.
// On error nothing is mutated.
func (s *CryptoService) SwapActive(hexKey string) (oldID, newID string, swapped bool, err error) {
	newEntry, err := parseKeyEntry(hexKey)
	if err != nil {
		return "", "", false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if newEntry.id == s.active.id {
		return s.active.id, s.active.id, false, nil
	}

	oldEntry := s.active
	s.active = newEntry
	// Demote the old active into the previous pool so ciphertexts encrypted
	// under it continue to decrypt. If the id is already present (same key
	// re-rotated into then out of active) the entry is overwritten with the
	// same material — no behavioural change.
	s.previous[oldEntry.id] = oldEntry

	return oldEntry.id, newEntry.id, true, nil
}

// Encrypt encrypts plaintext under the active key and returns the
// versioned ciphertext string. All new ciphertexts are v2-formatted.
func (s *CryptoService) Encrypt(plaintext string) (string, error) {
	s.mu.RLock()
	active := s.active
	s.mu.RUnlock()

	block, err := aes.NewCipher(active.material)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return "v2:" + active.id + ":" + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decodes any of the three supported ciphertext formats. v2
// ciphertexts look up their key by id; v1 and legacy ciphertexts have no
// id and are tried against the active key and then every previous key.
func (s *CryptoService) Decrypt(ciphertextB64 string) (string, error) {
	switch {
	case strings.HasPrefix(ciphertextB64, "v2:"):
		return s.decryptV2(ciphertextB64[len("v2:"):])
	case strings.HasPrefix(ciphertextB64, "v1:"):
		return s.decryptUnkeyed(ciphertextB64[len("v1:"):])
	default:
		return s.decryptUnkeyed(ciphertextB64)
	}
}

// decryptV2 parses "<keyID>:<b64>" and routes to the named key. A
// reference to an unknown id is a permanent failure — there is no
// fallback because any key used to seal a v2 ciphertext was either
// active or previous at encrypt time.
func (s *CryptoService) decryptV2(body string) (string, error) {
	sep := strings.IndexByte(body, ':')
	if sep <= 0 || sep == len(body)-1 {
		return "", errors.New("v2 ciphertext missing key id separator")
	}
	keyID := body[:sep]
	raw := body[sep+1:]

	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var material []byte
	switch keyID {
	case s.active.id:
		material = s.active.material
	default:
		entry, ok := s.previous[keyID]
		if !ok {
			return "", fmt.Errorf("unknown key id %q — ciphertext cannot be decrypted", keyID)
		}
		material = entry.material
	}
	return aesGCMOpen(material, data)
}

// decryptUnkeyed handles v1: and pre-v1 ciphertexts: same byte shape,
// different base64 alphabet, no key id. Tries the active key first,
// then every previous key in turn. Returns the first successful
// plaintext; otherwise the last error.
func (s *CryptoService) decryptUnkeyed(raw string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", fmt.Errorf("failed to decode ciphertext: %w", err)
		}
	}

	s.mu.RLock()
	candidates := make([][]byte, 0, 1+len(s.previous))
	candidates = append(candidates, s.active.material)
	for _, entry := range s.previous {
		candidates = append(candidates, entry.material)
	}
	s.mu.RUnlock()

	var lastErr error
	for _, material := range candidates {
		plaintext, err := aesGCMOpen(material, data)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no keys available to decrypt ciphertext")
	}
	return "", lastErr
}

// aesGCMOpen is the shared unseal step used by both decrypt paths. Split
// out so the format-decoding layer can focus on routing.
func aesGCMOpen(material, data []byte) (string, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
