package mappers

import (
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
)

func ToDomainSigningKey(dto types.SigningKey) domain.SigningKey {
	return domain.SigningKey{
		ID:          dto.ID,
		KID:         dto.KID,
		Algorithm:   domain.KeyAlgorithm(dto.Algorithm),
		PublicKey:   dto.PublicKey,
		PrivateKey:  dto.PrivateKey,
		State:       domain.KeyState(dto.State),
		CreatedAt:   dto.CreatedAt,
		ActivatedAt: dto.ActivatedAt,
		RotatedAt:   dto.RotatedAt,
		ExpiresAt:   dto.ExpiresAt,
		CreatedBy:   dto.CreatedBy,
	}
}

func ToDTOSigningKey(d domain.SigningKey) types.SigningKey {
	return types.SigningKey{
		ID:          d.ID,
		KID:         d.KID,
		Algorithm:   types.KeyAlgorithm(d.Algorithm),
		PublicKey:   d.PublicKey,
		PrivateKey:  d.PrivateKey,
		State:       types.KeyState(d.State),
		CreatedAt:   d.CreatedAt,
		ActivatedAt: d.ActivatedAt,
		RotatedAt:   d.RotatedAt,
		ExpiresAt:   d.ExpiresAt,
		CreatedBy:   d.CreatedBy,
	}
}

func ToDomainSigningKeys(dtos []types.SigningKey) []domain.SigningKey {
	result := make([]domain.SigningKey, len(dtos))
	for i, dto := range dtos {
		result[i] = ToDomainSigningKey(dto)
	}
	return result
}
