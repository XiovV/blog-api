package server

import (
	"fmt"
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

func validateToken(tok string) (*jwt.Token, error) {
	token, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("couldn't verify signing method")
		}

		return []byte(os.Getenv("SIGNING_KEY")), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

func getClaimString(token *jwt.Token, claim string) string {
	return token.Claims.(jwt.MapClaims)[claim].(string)
}

func getClaimInt(token *jwt.Token, claim string) int {
	return int(token.Claims.(jwt.MapClaims)[claim].(float64))
}
