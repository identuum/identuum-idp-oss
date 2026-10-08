package auth

import (
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// V6-110 (testbook): a kid built from the time to the second made two keys
// generated in the same second share an identifier. Two keys of each
// algorithm generated within one second must have different kids.
func TestGeneratedKeys_SameSecondHaveDifferentKIDs(t *testing.T) {
	for name, gen := range map[string]func() (*domain.SigningKey, error){
		"EdDSA": GenerateEdDSAKey, "ES256": GenerateES256Key, "RS256": GenerateRS256Key,
	} {
		t.Run(name, func(t *testing.T) {
			for attempt := 0; attempt < 5; attempt++ {
				before := time.Now().UTC().Unix()
				a, errA := gen()
				b, errB := gen()
				if errA != nil || errB != nil {
					t.Fatalf("generate: %v, %v", errA, errB)
				}
				if time.Now().UTC().Unix() != before {
					continue // the second changed between the two keys; try again
				}
				if a.KID == b.KID {
					t.Fatalf("two %s keys made in the same second share kid %q", name, a.KID)
				}
				return
			}
			t.Fatal("could not generate two keys within one second in five attempts")
		})
	}
}
