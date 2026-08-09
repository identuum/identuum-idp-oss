package domain

import "github.com/google/uuid"

type PublicIDPInfo struct {
	Name         string
	Type         string
	LoginURL     string
	EmailDomains []string
	ID           uuid.UUID
}

type OrganizationPublicConfig struct {
	Slug              string
	Name              string
	Domain            string
	AuthPolicy        string
	LoginURL          string
	RequestID         string
	IdentityProviders []PublicIDPInfo
}
