package server

import (
	"github.com/golang-jwt/jwt/v4"
	"os"
	"time"
)

type tokenClaims struct {
	ID int
	jwt.RegisteredClaims
}

func generateToken(id int) (string, error) {
	claims := tokenClaims{
		ID: id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(os.Getenv("SIGNING_KEY")))
	return ss, err
}
