package mappers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
	"github.com/stretchr/testify/assert"
)

func TestToDomainSigningKey(t *testing.T) {
	now := time.Now()
	dto := types.SigningKey{
		ID:        uuid.New(),
		KID:       "kid-1",
		Algorithm: types.KeyAlgorithmEdDSA,
		CreatedAt: now,
	}

	domainKey := ToDomainSigningKey(dto)
	assert.Equal(t, dto.ID, domainKey.ID)
	assert.Equal(t, dto.KID, domainKey.KID)
	assert.Equal(t, domain.KeyAlgorithm(dto.Algorithm), domainKey.Algorithm)
	assert.Equal(t, now, domainKey.CreatedAt)

	// Array tests
	dtos := []types.SigningKey{dto}
	domainKeys := ToDomainSigningKeys(dtos)
	assert.Len(t, domainKeys, 1)
	assert.Equal(t, dto.ID, domainKeys[0].ID)
}

func TestToDTOSigningKey(t *testing.T) {
	now := time.Now()
	domainKey := domain.SigningKey{
		ID:        uuid.New(),
		KID:       "kid-1",
		Algorithm: domain.KeyAlgorithmEdDSA,
		CreatedAt: now,
	}

	dto := ToDTOSigningKey(domainKey)
	assert.Equal(t, domainKey.ID, dto.ID)
	assert.Equal(t, domainKey.KID, dto.KID)
	assert.Equal(t, types.KeyAlgorithm(domainKey.Algorithm), dto.Algorithm)
	assert.Equal(t, now, dto.CreatedAt)
}
