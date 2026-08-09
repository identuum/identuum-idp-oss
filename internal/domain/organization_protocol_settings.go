package domain

import (
	"time"

	"github.com/google/uuid"
)

// OrganizationProtocolSettings is the per-organization config that
// gates the OSS DCR and SCIM foundation handlers at request time.
// One row per organization is the storage model; an absent row is
// equivalent to a row whose booleans are FALSE.
//
// Owner correction (2026-06-04): protocol availability is per-org
// DB state, NOT a global env variable. See
// `identuum-idp/docs/open-core/IDP_DCR_SCIM_ORG_LEVEL_DB_CONFIG_CORRECTION.md`.
type OrganizationProtocolSettings struct {
	OrganizationID uuid.UUID
	DCREnabled     bool
	SCIMEnabled    bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
