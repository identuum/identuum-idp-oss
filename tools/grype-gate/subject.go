package main

// subject.go — THE-JUDGE-AND-ITS-SUBJECT (2026-09-12).
//
// A grype report says what it judged: `source.type` is "directory" or
// "image" and `source.target` is the directory path AS GIVEN to the scanner
// (so "." is relative to the scanner's working directory) or, for an image,
// an object whose userInput is the reference the caller named. The two
// predicates THE-GRYPE-SUBJECT added — the applied configuration (a) and the
// exclude coverage (b) — are statements about a DIRECTORY: they read the
// subject's own .grype.yaml and enumerate the subject's own gitignored
// executables. An image carries neither, so for an image subject both are
// NOT APPLICABLE: reported as such on the evidence line, never passed
// silently and never counted as failures; the vulnerability verdict stays
// the gate. And for a directory subject the predicates read THE SUBJECT'S
// tree, never the caller's: identuum-ui drives this judge with
// `go run -C ../identuum-idp-oss`, which made "." this repository, so the
// judge compared identuum-ui's image scan with identuum-idp-oss's declaration
// (red since e12bd79) and, worse, enumerated identuum-idp-oss's gitignored
// executables as if they were identuum-ui's.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Subject is what a report judged, read from the report's own source block.
type Subject struct {
	// Kind is grype's source.type: "directory", "image", or whatever else the
	// scanner wrote (judged as unknown).
	Kind string
	// Target is the directory path as given to the scanner, or the image
	// reference the caller named (source.target.userInput).
	Target string
}

// ParseSubject reads the subject from a grype JSON report. A report without a
// source block is not a judgeable report.
func ParseSubject(raw []byte) (Subject, error) {
	var doc struct {
		Source *struct {
			Type   string          `json:"type"`
			Target json.RawMessage `json:"target"`
		} `json:"source"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Subject{}, fmt.Errorf("grype output: invalid JSON: %w", err)
	}
	if doc.Source == nil || doc.Source.Type == "" {
		return Subject{}, fmt.Errorf("grype output: no source block — the report does not say what it judged")
	}
	s := Subject{Kind: doc.Source.Type}
	switch s.Kind {
	case "directory":
		var path string
		if err := json.Unmarshal(doc.Source.Target, &path); err != nil {
			return Subject{}, fmt.Errorf("grype output: directory source.target is not a path: %w", err)
		}
		s.Target = path
	case "image":
		var img struct {
			UserInput string `json:"userInput"`
		}
		if err := json.Unmarshal(doc.Source.Target, &img); err != nil {
			return Subject{}, fmt.Errorf("grype output: image source.target is not an image descriptor: %w", err)
		}
		s.Target = img.UserInput
	default:
		s.Target = strings.TrimSpace(string(doc.Source.Target))
	}
	return s, nil
}

// IsDirectory reports whether the predicates (a) and (b) apply.
func (s Subject) IsDirectory() bool { return s.Kind == "directory" }

// IsImage reports whether the predicates are not applicable.
func (s Subject) IsImage() bool { return s.Kind == "image" }

// Label names the subject on the evidence line: "directory:/abs/path" or
// "image:name:tag".
func (s Subject) Label() string {
	if s.Target == "" {
		return s.Kind
	}
	return s.Kind + ":" + s.Target
}

// ResolveDir returns the directory the predicates must read for a DIRECTORY
// subject. An absolute target is the subject itself, and a -root that names a
// different directory is refused: the judge must not report facts about the
// caller's checkout. A relative target (grype records "." for `dir:.`) is
// relative to the scanner's working directory, which the caller knows and
// the report does not, so the caller's root is the subject.
func (s Subject) ResolveDir(root string, rootExplicit bool) (string, error) {
	if !s.IsDirectory() {
		return "", fmt.Errorf("grype-gate: subject %s is not a directory", s.Label())
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("grype-gate cannot resolve root %s (%v)", root, err)
	}
	if !filepath.IsAbs(s.Target) {
		return absRoot, nil
	}
	target := filepath.Clean(s.Target)
	if rootExplicit && target != absRoot {
		return "", fmt.Errorf("grype-gate: -root %s is not the scan's subject %s — the predicates read the subject's tree, never the caller's", absRoot, target)
	}
	return target, nil
}
