package types

import "errors"

var ErrNoAuditRepo = errors.New("audit repository not configured")

// Sentinel errors for database operations
// These errors are returned by database functions and checked using errors.Is()
var (
	ErrUserNotFound         = errors.New("user not found")
	ErrOrgNotFound          = errors.New("organization not found")
	ErrRefreshTokenReuse    = errors.New("refresh token reuse detected")
	ErrTransactionCompleted = errors.New("transaction already completed")
)

// Error message constants for external API responses
// These generic messages prevent information disclosure while maintaining usability
const (
	// Generic server errors
	ErrMsgGenericServer    = "An error occurred. Please try again later."
	ErrMsgGenericAuth      = "Authentication failed"
	ErrMsgInvalidRequest   = "Invalid request format"
	ErrMsgAccessDenied     = "Access denied"
	ErrMsgResourceNotFound = "Resource not found"
	ErrMsgOperationFailed  = "Operation could not be completed"
	ErrMsgWeakPassword     = "Password must be at least 8 characters long and contain varied characters"

	// Authentication specific
	// #nosec G101 - False positive: This is an error message constant, not a credential
	ErrMsgInvalidCredentials = "Invalid credentials"
	ErrMsgTokenExpired       = "Session expired"
	ErrMsgTokenInvalid       = "Invalid token"
	ErrMsgNoToken            = "Authentication required"

	// Input validation
	ErrMsgInvalidEmail    = "Invalid email format"
	ErrMsgInvalidInput    = "Invalid input provided"
	ErrMsgMissingRequired = "Required fields are missing"
	ErrMsgInvalidFormat   = "Invalid data format"

	// Authorization
	ErrMsgInsufficientPerms = "Insufficient permissions"
	ErrMsgOrgAccessDenied   = "Organization access denied"
	ErrMsgRoleRequired      = "Required role not found"

	// Rate limiting and security
	ErrMsgRateLimited    = "Too many requests. Please try again later."
	ErrMsgSessionRevoked = "Session has been revoked"

	// Success messages
	SuccessMsgGeneric       = "Operation completed successfully"
	SuccessMsgLogin         = "Login successful"
	SuccessMsgLogout        = "Logout successful"
	SuccessMsgCreated       = "Resource created successfully"
	SuccessMsgUpdated       = "Resource updated successfully"
	SuccessMsgDeleted       = "Resource deleted successfully"
	SuccessMsgDataRetrieved = "Data retrieved successfully"
)
