package server

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/XiovV/blog-api/config"
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"net/http"
	"os"
)

const (
	LOCAL_ENV   = "LOCAL"
	STAGING_ENV = "STAGING"
	PROD_ENV    = "PRODUCTION"
)

type Server struct {
	Config         *config.Config
	UserRepository *repository.UserRepository
	PostRepository *repository.PostRepository
	Logger         *zap.Logger

	gcm cipher.AEAD
}

func (s *Server) Run() error {
	gcm, err := s.setupGcm()
	if err != nil {
		return err
	}

	s.gcm = gcm

	if os.Getenv("ENV") == PROD_ENV {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), s.CORS())

	v1 := router.Group("/v1")

	usersPublic := v1.Group("/users")
	{
		usersPublic.POST("/register", s.registerUserHandler)
		usersPublic.POST("/login", s.loginUserHandler)
		usersPublic.POST("/login/mfa", s.loginUserMfaHandler)
	}

	usersAuth := v1.Group("/users")
	usersAuth.Use(s.userAuth)
	{
		usersAuth.POST("/mfa", s.setupMfaHandler)
		usersAuth.POST("/mfa/confirm", s.confirmMfaHandler)
	}

	postsAuth := v1.Group("/posts")
	postsAuth.Use(s.userAuth)
	{
		postsAuth.POST("/", s.createPostHandler)
	}

	err = http.ListenAndServe(":"+s.Config.Port, router)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) setupGcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher([]byte(s.Config.AESKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}
