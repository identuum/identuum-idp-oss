package domain

// ScopeDescriptions maps scope constants to human-readable strings for the Consent Screen
var ScopeDescriptions = map[string]string{
	ScopeOpenID:        "Verify your identity (OpenID Connect)",
	ScopeProfile:       "View your basic profile information (Name, Picture)",
	ScopeEmail:         "View your email address",
	ScopeAddress:       "View your postal address",
	ScopePhone:         "View your phone number",
	ScopeOfflineAccess: "Access your account while you are not logged in (Refresh Token)",

	ScopeUsersRead:   "View users in your organization",
	ScopeUsersCreate: "Create new users",
	ScopeUsersUpdate: "Update user details",
	ScopeUsersDelete: "Delete users",

	ScopeOrgsRead:   "View organization details",
	ScopeOrgsCreate: "Create new organizations",
	ScopeOrgsUpdate: "Update organization settings",
	ScopeOrgsDelete: "Delete organizations",

	ScopeAuditRead: "View audit logs",

	ScopeReportsRead: "View system reports",
}

// GetScopeDescription returns the description for a given scope, or the scope itself if unknown
func GetScopeDescription(scope string) string {
	if desc, ok := ScopeDescriptions[scope]; ok {
		return desc
	}
	return scope
}
