package server

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/XiovV/blog-api/config"
	"github.com/XiovV/blog-api/pkg/mailer"
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/casbin/casbin/v2"
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
	CasbinEnforcer *casbin.Enforcer
	Mailer         *mailer.Mailer

	gcm cipher.AEAD
}

// Run -.
// Swagger spec:
// @title       Simple Blog API
// @version     1.0
// @host        localhost:8080
// @BasePath    /v1
// @securityDefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
func (s *Server) Run() error {
	err := s.setupGcm()
	if err != nil {
		return err
	}

	if s.Config.Environment == PROD_ENV {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), s.CORS(), s.errorHandler())

	v1 := router.Group("/v1")

	v1.GET("/health", s.healthCheck)

	usersPublic := v1.Group("/users")
	{
		usersPublic.POST("/register", s.registerUserHandler)
		usersPublic.POST("/login", s.loginUserHandler)
		usersPublic.POST("/login/mfa", s.loginUserMfaHandler)
		usersPublic.POST("/login/recovery", s.loginUserRecoveryHandler)
		usersPublic.POST("/token/refresh", s.refreshTokenHandler)
		usersPublic.POST("/password-reset", s.createPasswordResetToken)
		usersPublic.PUT("/password-reset", s.resetUserPasswordHandler)
	}

	usersAuth := v1.Group("/users")
	usersAuth.Use(s.userAuth)
	{
		usersAuth.POST("/mfa", s.setupMfaHandler)
		usersAuth.POST("/mfa/confirm", s.confirmMfaHandler)
		usersAuth.GET("/posts", s.getPersonalPostsHandler)
		usersAuth.DELETE("/:userId", s.deleteUserHandler)
	}

	postsAuth := v1.Group("/posts")
	postsAuth.Use(s.userAuth)
	{
		postsAuth.POST("/", s.createPostHandler)
		postsAuth.GET("/:postId", s.getPostHandler)
		postsAuth.DELETE("/:postId", s.deletePostHandler)
		postsAuth.GET("/user/:username", s.getUserPostsHandler)
		postsAuth.PUT("/:postId", s.editPostHandler)
	}

	s.Logger.Info("server listening...", zap.String("port", s.Config.Port), zap.String("env", s.Config.Environment))
	err = http.ListenAndServe(":"+s.Config.Port, router)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) setupGcm() error {
	block, err := aes.NewCipher([]byte(s.Config.AESKey))
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	s.gcm = gcm

	return nil
}

func (s *Server) healthCheck(c *gin.Context) {
	hostname, err := os.Hostname()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{"version": "1.0.1", "host": hostname})
}
