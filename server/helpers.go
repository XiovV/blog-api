package server

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"math/rand"
	"strconv"
)

const (
	MaxLimitValue       = 100
	MinLimitValue       = 1
	MinPageValue        = 1
	RecoveryCodesAmount = 16
	RecoveryCodeLength  = 7
)

func (s *Server) validatePageAndLimit(c *gin.Context) (int, int, error) {
	page, err := strconv.Atoi(c.Query("page"))
	if err != nil {
		return 0, 0, fmt.Errorf("page must be an integer")
	}

	limit, err := strconv.Atoi(c.Query("limit"))
	if err != nil {
		return 0, 0, fmt.Errorf("limit must be an integer")
	}

	if page < MinPageValue {
		return 0, 0, fmt.Errorf("page must be greater than 0")
	}

	if limit < MinLimitValue {
		return 0, 0, fmt.Errorf("limit must be greater than 0")
	}

	if limit > MaxLimitValue {
		return 0, 0, fmt.Errorf("maximum limit size is %d", MaxLimitValue)
	}

	return page, limit, nil
}

func (s *Server) encryptMfaSecret(secret []byte) []byte {
	nonce := make([]byte, s.gcm.NonceSize())
	return s.gcm.Seal(nonce, nonce, secret, nil)
}

func (s *Server) decryptMfaSecret(encryptedSecret []byte) ([]byte, error) {
	nonceSize := s.gcm.NonceSize()
	nonce, cipherText := encryptedSecret[:nonceSize], encryptedSecret[nonceSize:]
	return s.gcm.Open(nil, nonce, cipherText, nil)
}

func (s *Server) generateRecoveryCodes() []string {
	codes := []string{}

	for i := 0; i <= RecoveryCodesAmount; i++ {
		codes = append(codes, randomString())
	}

	return codes
}

func randomString() string {
	charset := []byte("abcdefghijklmnopqrstuvwxyz")

	b := make([]byte, RecoveryCodeLength)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}