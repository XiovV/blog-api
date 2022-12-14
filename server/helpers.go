package server

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

const (
	MaxLimitValue            = 100
	MinLimitValue            = 1
	MinPageValue             = 1
	RecoveryCodesAmount      = 16
	RecoveryCodeLength       = 7
	PasswordResetTokenLength = 20
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

func generateRecoveryCodes() []string {
	codes := []string{}

	for i := 0; i <= RecoveryCodesAmount; i++ {
		codes = append(codes, randomString(RecoveryCodeLength))
	}

	return codes
}

func (s *Server) validateAuthorizationHeader(c *gin.Context) (string, error) {
	tokenHeader := c.GetHeader("Authorization")

	if len(tokenHeader) == 0 {
		return "", errors.New("did not receive Authorization header")
	}

	authorizationHeaderSplit := strings.Split(tokenHeader, " ")
	if len(authorizationHeaderSplit) != 2 {
		return "", errors.New("wrong Authorization header format")
	}

	if authorizationHeaderSplit[0] != "Bearer" {

		return "", errors.New("wrong Authorization header format")
	}

	return authorizationHeaderSplit[1], nil
}

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())

	charset := []byte("abcdefghijklmnopqrstuvwxyz")

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}

func removeRecoveryCode(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func (s *Server) isRecoveryCodeValid(recoveryCode string, codes []string) bool {
	for _, code := range codes {
		if recoveryCode == code {
			return true
		}
	}

	return false
}

func (s *Server) enforcePermissions(c *gin.Context, role, object, action string) bool {
	ok, err := s.CasbinEnforcer.Enforce(role, "user", "delete")
	if err != nil {
		s.Logger.Debug("couldn't enforce rules", zap.Error(err))
		s.internalServerErrorResponse(c)
		return false
	}

	return ok
}
