package main

import (
	"fmt"
	"github.com/XiovV/blog-api/config"
	"github.com/XiovV/blog-api/pkg/repository"
	"github.com/XiovV/blog-api/server"
	"go.uber.org/zap"
	"log"
)

func main() {
	c, err := config.New()
	if err != nil {
		log.Fatalln("config err:", err)
	}

	fmt.Println(c)

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
		Config:         c,
		UserRepository: userRepository,
		Logger:         logger,
	}

	if err := s.Run(); err != nil {
		logger.Error("couldn't start server", zap.Error(err))
	}
}
