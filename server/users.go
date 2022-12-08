package server

import (
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/XiovV/blog-api/pkg/validator"
	"github.com/alexedwards/argon2id"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"net/mail"
	"strings"
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
		c.JSON(http.StatusBadRequest, gin.H{"err": errors})
		return
	}

	_, err := mail.ParseAddress(request.Email)
	if err != nil {
		s.Logger.Info("email is invalid")
		c.JSON(http.StatusBadRequest, gin.H{"err": "email is invalid"})
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
		c.JSON(http.StatusBadRequest, gin.H{"err": "username or email are already taken"})
		return
	}

	token, err := generateToken(id)
	if err != nil {
		s.Logger.Error("couldn't generate token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"err": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"jwt": token})
}
