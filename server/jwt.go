package server

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"os"
	"time"
)

const (
	AccessTokenExpiry = 15
	//RefreshTokenExpiry 17532 = 2 years
	RefreshTokenExpiry = 17532
	RefreshTokenType   = "REFRESH"
)

type tokenClaims struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	jwt.RegisteredClaims
}

func generateAccessToken(id int) (string, error) {
	claims := tokenClaims{
		ID: id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenExpiry * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(os.Getenv("SIGNING_KEY")))
	return ss, err
}

func generateRefreshToken(id int) (string, error) {
	claims := tokenClaims{
		ID:   id,
		Type: RefreshTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenExpiry * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(os.Getenv("SIGNING_KEY")))
	return ss, err
}

func parseToken(tok string) (*jwt.Token, error) {
	token, _ := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("couldn't verify signing method")
		}

		return []byte(os.Getenv("SIGNING_KEY")), nil
	})

	return token, nil
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

func validateRefreshToken(tok string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tok, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SIGNING_KEY")), nil
	})

	if !token.Valid {
		return nil, err
	}

	if claims, ok := token.Claims.(*tokenClaims); ok {
		if claims.Type != RefreshTokenType {
			return nil, errors.New("token is not a refresh token")
		}
	}

	return token, nil
}

func getClaimString(token *jwt.Token, claim string) string {
	return token.Claims.(jwt.MapClaims)[claim].(string)
}

func getClaimInt(token *jwt.Token, claim string) int {
	return int(token.Claims.(jwt.MapClaims)[claim].(float64))
}
