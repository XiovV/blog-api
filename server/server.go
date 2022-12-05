package server

import (
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
	UserRepository *repository.UserRepository
	Logger         *zap.Logger
}

func (s *Server) Run(port string) error {
	if os.Getenv("ENV") == PROD_ENV {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), s.CORS())

	v1 := router.Group("/v1")

	usersPublic := v1.Group("/users")
	{
		usersPublic.POST("/register", s.registerUserHandler)
		usersPublic.POST("/login")
	}

	err := http.ListenAndServe(":"+port, router)
	if err != nil {
		return err
	}

	return nil
}
