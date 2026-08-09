package uuidgen

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewV7(t *testing.T) {
	id, err := NewV7()
	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, id)
	assert.Equal(t, uuid.Version(7), id.Version())
}

func TestNewV7String(t *testing.T) {
	str, err := NewV7String()
	assert.NoError(t, err)
	assert.NotEmpty(t, str)

	parsed, err := uuid.Parse(str)
	assert.NoError(t, err)
	assert.Equal(t, uuid.Version(7), parsed.Version())
}

func TestNewV7_RetryExhaustion(t *testing.T) {
	original := newV7Func
	t.Cleanup(func() { newV7Func = original })

	stubErr := errors.New("clock regression")
	newV7Func = func() (uuid.UUID, error) {
		return uuid.Nil, stubErr
	}

	id, err := NewV7()
	assert.Equal(t, uuid.Nil, id)
	assert.ErrorIs(t, err, stubErr)
	assert.Contains(t, err.Error(), "uuid v7 generation failed after 3 attempts")
}
