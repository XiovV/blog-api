package main

import (
	"github.com/XiovV/blog-api/config"
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/XiovV/blog-api/server"
	"go.uber.org/zap"
	"log"
)

func main() {
	c, err := config.New()
	if err != nil {
		log.Fatalln(err)
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

	s := server.Server{
		UserRepository: userRepository,
		Logger:         logger,
	}

	if err := s.Run(c.Port); err != nil {
		logger.Error("couldn't start server", zap.Error(err))
	}
}
