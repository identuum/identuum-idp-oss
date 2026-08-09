package filepaths

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SecureJoin joins a base directory with a user-provided path securely,
// ensuring the resulting path does not escape the base directory.
func SecureJoin(base, userPath string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}

	cleanUser := filepath.Clean(userPath)
	var finalPath string

	if filepath.IsAbs(cleanUser) {
		finalPath = cleanUser
	} else {
		finalPath = filepath.Join(absBase, cleanUser)
	}

	// Ensure finalPath stays within absBase by checking prefix
	// We add a separator to ensure /app/data doesn't falsely match /app/data2
	if !strings.HasPrefix(finalPath, absBase+string(filepath.Separator)) && finalPath != absBase {
		return "", fmt.Errorf("path escapes base directory")
	}

	return finalPath, nil
}
