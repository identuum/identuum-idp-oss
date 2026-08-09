package crypto

import (
	"strings"
	"testing"
)

// P3-6: Argon2 parameters are read from the STORED PHC string and passed
// straight to argon2.IDKey. A corrupt or hostile row can therefore choose the
// server's memory and CPU cost at verification time — m= is a uint32, so the
// ceiling is 4 TiB of allocation per login attempt. The hash need not be valid;
// the cost is paid BEFORE the comparison fails.
func TestVerifyPassword_RejectsAbsurdArgon2Parameters(t *testing.T) {
	// A well-formed PHC string in every respect except the cost parameters.
	hostile := "$argon2id$v=19$m=4294967295,t=4294967295,p=255$c29tZXNhbHQ$c29tZWhhc2g"
	if err := CompareHashAndPassword([]byte(hostile), []byte("hunter2")); err == nil {
		t.Fatal("absurd Argon2 parameters were ACCEPTED for evaluation; " +
			"m=4294967295 is a 4 TiB allocation chosen by whoever wrote the row")
	} else if !strings.Contains(err.Error(), "format") && err != ErrInvalidHashFormat {
		t.Logf("rejected with: %v", err)
	}
}
