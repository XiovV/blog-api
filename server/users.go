package server

import (
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/XiovV/blog-api/pkg/validator"
	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"net/http"
	"net/mail"
	"strings"
)

const (
	totpSecretLength = 32
	totpCodeLength   = 6
)

func (s *Server) registerUserHandler(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		s.invalidJSONResponse(c)
		return
	}

	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.TrimSpace(request.Email)

	v := validator.New()

	v.RequiredMax("username", request.Username, 50)
	v.RequiredMin("password", request.Password, 8)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Info("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	_, err := mail.ParseAddress(request.Email)
	if err != nil {
		s.Logger.Info("email is invalid", zap.String("email", request.Email))
		s.badRequestResponse(c, "email is invalid")
		return
	}

	hash, err := argon2id.CreateHash(request.Password, &argon2id.Params{
		Memory:      128 * 1024,
		Iterations:  10,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	})

	id, err := s.UserRepository.InsertUser(repository.User{Username: request.Username, Email: request.Email, Password: hash})
	if err != nil {
		s.Logger.Debug("couldn't insert user", zap.Error(err))
		s.badRequestResponse(c, "username or email are already taken")
		return
	}

	token, err := generateToken(id)
	if err != nil {
		s.Logger.Error("couldn't generate token", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{"jwt": token})
}

func (s *Server) loginUserHandler(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		s.invalidJSONResponse(c)
		return
	}

	request.Username = strings.TrimSpace(request.Username)

	v := validator.New()

	v.RequiredMax("username", request.Username, 50)
	v.RequiredMin("password", request.Password, 8)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Info("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	user, err := s.UserRepository.FindUserByUsername(request.Username)
	if err != nil {
		s.Logger.Error("couldn't find user", zap.Error(err))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	ok, err = argon2id.ComparePasswordAndHash(request.Password, user.Password)
	if err != nil {
		s.Logger.Error("couldn't check hash", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	if !ok {
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	if len(user.MFASecret) != 0 {
		c.Status(http.StatusFound)
		return
	}

	token, err := generateToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate token", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{"jwt": token})
}

func (s *Server) loginUserMfaHandler(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		s.invalidJSONResponse(c)
		return
	}

	request.Username = strings.TrimSpace(request.Username)

	v := validator.New()

	v.RequiredMax("username", request.Username, 50)
	v.RequiredMin("password", request.Password, 8)

	ok, errors := v.IsValid()
	if !ok {
		s.Logger.Info("input invalid", zap.Strings("err", errors))
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	user, err := s.UserRepository.FindUserByUsername(request.Username)
	if err != nil {
		s.Logger.Error("couldn't find user", zap.Error(err))
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	ok, err = argon2id.ComparePasswordAndHash(request.Password, user.Password)
	if err != nil {
		s.Logger.Error("couldn't check hash", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	if !ok {
		s.badRequestResponse(c, "incorrect username or password")
		return
	}

	if len(user.MFASecret) == 0 {
		s.badRequestResponse(c, "this user doesn't have 2fa enabled")
		return
	}

	secret, err := s.decryptMfaSecret(user.MFASecret)
	if err != nil {
		s.Logger.Error("couldn't decrypt secret", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	ok = totp.Validate(request.TOTP, string(secret))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid totp code"})
		return
	}

	token, err := generateToken(user.ID)
	if err != nil {
		s.Logger.Error("couldn't generate token", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{"jwt": token})
}

func (s *Server) setupMfaHandler(c *gin.Context) {
	user := s.getUserFromContext(c)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "blog-api", AccountName: user.Username})
	if err != nil {
		s.Logger.Error("couldn't generate secret", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{"secret": key.Secret()})
}

func (s *Server) confirmMfaHandler(c *gin.Context) {
	user := s.getUserFromContext(c)

	var request struct {
		Secret string `json:"secret"`
		TOTP   string `json:"totp"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		s.invalidJSONResponse(c)
		return
	}

	v := validator.New()
	v.RequiredExact("secret", request.Secret, totpSecretLength)
	v.RequiredExact("totp", request.TOTP, totpCodeLength)

	ok, errors := v.IsValid()
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors})
		return
	}

	ok = totp.Validate(request.TOTP, request.Secret)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid totp code"})
		return
	}

	encryptedSecret := s.encryptMfaSecret([]byte(request.Secret))

	err := s.UserRepository.InsertMfaSecret(user.ID, encryptedSecret)
	if err != nil {
		s.Logger.Error("couldn't insert secret", zap.Error(err))
		s.internalServerErrorResponse(c)
		return
	}

	c.Status(http.StatusOK)
}
