package main

import (
	"github.com/XiovV/blog-api/config"
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/XiovV/blog-api/server"
	"github.com/casbin/casbin/v2"
	"go.uber.org/zap"
	"log"
)

func main() {
	c, err := config.New()
	if err != nil {
		log.Fatalln("config err:", err)
	}

	logger, err := initLogger()
	if err != nil {
		log.Fatalln(err)
	}

	db, err := repository.NewPostgres(c.PostgresDSN)
	if err != nil {
		logger.Error("couldn't initialise a database connection", zap.Error(err))
		return
	}

	userRepository := repository.NewUserRepository(db)
	postRepository := repository.NewPostRepository(db)

	enforcer, err := casbin.NewEnforcer("rbac/rbac_model.conf", "rbac/rbac_policy.csv")
	if err != nil {
		logger.Error("couldn't init enforcer", zap.Error(err))
		return
	}

	s := server.Server{
		Config:         c,
		UserRepository: userRepository,
		PostRepository: postRepository,
		Logger:         logger,
		CasbinEnforcer: enforcer,
	}

	if err := s.Run(); err != nil {
		logger.Error("couldn't start server", zap.Error(err))
	}
}
