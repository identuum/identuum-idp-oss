package filepaths

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureJoin(t *testing.T) {
	absBase, _ := filepath.Abs("/app/data")

	tests := []struct {
		name      string
		base      string
		userPath  string
		expectErr bool
	}{
		{"Valid Relative", "/app/data", "audit.log", false},
		{"Valid Deep Relative", "/app/data", "logs/audit.log", false},
		{"Valid Absolute Inside", "/app/data", "/app/data/logs/audit.log", false},
		{"Valid Same Dir", "/app/data", "/app/data", false},
		{"Invalid Absolute Outside", "/app/data", "/tmp/evil.log", true},
		{"Invalid Relative Traversal", "/app/data", "../../etc/passwd", true},
		{"Invalid Trick Dir", "/app/data", "/app/data2/audit.log", true},
		// Fix 1: empty userPath — filepath.Clean("") returns ".", which
		// filepath.Join collapses to absBase. Confirms no escape occurs.
		{"Empty userPath", "/app/data", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SecureJoin(tt.base, tt.userPath)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for %s, got nil (result: %s)", tt.userPath, result)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, got %v", tt.userPath, err)
				}
				expected := filepath.Join(absBase, filepath.Clean(tt.userPath))
				if filepath.IsAbs(tt.userPath) {
					expected = filepath.Clean(tt.userPath)
				}
				if result != expected {
					t.Errorf("Expected %s, got %s", expected, result)
				}
			}
		})
	}

	// Fix 2: null byte in userPath.
	// filepath.Clean does NOT strip null bytes; the returned path will contain
	// the null byte. SecureJoin itself does not error — the path still passes
	// the absBase prefix check. Defence is at the OS syscall layer: any
	// subsequent os.Open / os.Create call will fail with EINVAL. This test
	// documents that behaviour to prevent future misunderstanding.
	t.Run("Null byte in userPath", func(t *testing.T) {
		nullPath := "audit\x00evil.log"
		result, err := SecureJoin("/app/data", nullPath)
		if err != nil {
			t.Errorf("SecureJoin should not error on null-byte path (OS rejects at syscall layer), got: %v", err)
		}
		// The result must still be rooted under absBase.
		if !strings.HasPrefix(result, absBase+string(filepath.Separator)) {
			t.Errorf("Expected result to be under %s, got %s", absBase, result)
		}
	})
}
