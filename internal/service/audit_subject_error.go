package service

import "github.com/google/uuid"

// AuditSubjectError retains a subject resolved from trusted storage on a failed
// operation. It carries no credential or session material and preserves errors.Is.
type AuditSubjectError struct {
	SubjectID      uuid.UUID
	OrganizationID uuid.UUID
	Err            error
}

func (e *AuditSubjectError) Error() string { return e.Err.Error() }
func (e *AuditSubjectError) Unwrap() error { return e.Err }
