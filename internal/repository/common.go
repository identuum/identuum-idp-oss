package repository

import "time"

// UserFilter represents filtering options for user queries
type UserFilter struct {
	Banned           *bool  // Filter by banned status (nil = no filter)
	EmailVerified    *bool  // Filter by email verified status
	Deleted          *bool  // Filter by deleted status (nil = no filter)
	IncludeDeleted   bool   // If true, ignores default "deleted=false" filter when Deleted is nil
	Search           string // Search term for text fields (searches across name, email, org name)
	Role             string // Filter by specific role (empty = no filter)
	Email            string // Filter by email (partial match)
	Name             string // Filter by name (partial match)
	OrganizationName string // Filter by organization name (partial match)
}

// OrganizationFilter represents filtering options for organization queries
type OrganizationFilter struct {
	Active          *bool  // Filter by active status (nil = no filter)
	Deleted         *bool  // Filter by deleted status (nil = no filter)
	IncludeDeleted  bool   // If true, ignores default "deleted=false" filter when Deleted is nil
	IncludeInactive bool   // If true, ignores default "active=true" filter when Active is nil
	Search          string // Search term for text fields (searches across name, domain)
	Name            string // Filter by name (partial match)
	Domain          string // Filter by domain (partial match)
}

// Filter is deprecated - use UserFilter or OrganizationFilter instead
// Keeping for backward compatibility during migration
type Filter struct {
	Active           *bool  // Filter by active status (nil = no filter)
	Deleted          *bool  // Filter by deleted status (nil = no filter)
	Search           string // Search term for text fields (searches across name, email, org name)
	Role             string // Filter by specific role (empty = no filter)
	Email            string // Filter by email (partial match)
	Name             string // Filter by name (partial match)
	OrganizationName string // Filter by organization name (partial match)
}

// Pagination represents pagination parameters
type Pagination struct {
	Page     int // Page number (1-based)
	PageSize int // Items per page
	Offset   int // Calculated offset for database queries
}

// NewPagination creates a Pagination with calculated offset
func NewPagination(page, pageSize int) Pagination {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100 // Max page size
	}

	return Pagination{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}
}

// Sort represents sorting options
type Sort struct {
	Field string // Field to sort by (id, email, name, role, active, deleted, created_at, last_login_at)
	Desc  bool   // Sort descending if true (asc if false)
}

// ValidUserSortFields are the allowed fields for sorting users
var ValidUserSortFields = map[string]bool{
	"id":             true,
	"email":          true,
	"name":           true,
	"role":           true,
	"banned":         true,
	"email_verified": true,
	"deleted":        true,
	"created_at":     true,
	"last_login_at":  true,
}

// ValidOrganizationSortFields are the allowed fields for sorting organizations
var ValidOrganizationSortFields = map[string]bool{
	"id":         true,
	"name":       true,
	"domain":     true,
	"active":     true,
	"deleted":    true,
	"created_at": true,
}

// ValidSortFields is deprecated - use ValidUserSortFields or ValidOrganizationSortFields
// Keeping for backward compatibility
var ValidSortFields = map[string]bool{
	"id":             true,
	"email":          true,
	"name":           true,
	"role":           true,
	"banned":         true,
	"email_verified": true,
	"active":         true, // Kept for orgs
	"deleted":        true,
	"created_at":     true,
	"last_login_at":  true,
}

// NewUserSort creates a Sort for user queries with validation
func NewUserSort(field string, desc bool) Sort {
	// Default to created_at if invalid field
	if !ValidUserSortFields[field] {
		field = "created_at"
	}
	return Sort{
		Field: field,
		Desc:  desc,
	}
}

// NewOrganizationSort creates a Sort for organization queries with validation
func NewOrganizationSort(field string, desc bool) Sort {
	// Default to created_at if invalid field
	if !ValidOrganizationSortFields[field] {
		field = "created_at"
	}
	return Sort{
		Field: field,
		Desc:  desc,
	}
}

// DateRange represents a date range filter
type DateRange struct {
	Start *time.Time
	End   *time.Time
}

// PaginatedResult represents a paginated result set
type PaginatedResult struct {
	TotalCount int // Total number of items
	Page       int // Current page
	PageSize   int // Items per page
	TotalPages int // Total number of pages
	Data       any // Actual data (slice of entities)
}
