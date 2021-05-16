package jwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateJWT(t *testing.T) {
	jwt := LoadJwt("test")

	str, err := jwt.GenerateJWT(SessionDetail{
		UserId:    "A",
		SessionId: "B",
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, str)
}

func TestGenerateBackAndForth(t *testing.T) {
	jwt := LoadJwt("test")

	str, err := jwt.GenerateJWT(SessionDetail{
		UserId:    "A",
		SessionId: "B",
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, str)

	///

	data, err := jwt.ParseToken(str)

	assert.NoError(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, data.UserId, "A")
	assert.Equal(t, data.SessionId, "B")
}
