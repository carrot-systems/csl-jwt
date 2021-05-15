package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

func LoadJwt(key string) *JwtInstance {
	return &JwtInstance{
		Key: key,
	}
}

func (j *JwtInstance) ParseToken(token string) (*Claims, error) {
	claims := &Claims{}

	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.Key, nil
	})

	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (j *JwtInstance) generateJWT(session SessionDetail) (string, error) {
	expirationTime := time.Now().Add(5 * 24 * time.Hour)

	claims := &Claims{
		SessionDetail: session,

		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(j.Key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
