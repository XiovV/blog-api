package main

import (
	"github.com/XiovV/blog-api/server"
	"go.uber.org/zap"
	"os"
)

func initLogger() (*zap.Logger, error) {
	if os.Getenv("ENV") == server.LOCAL_ENV || os.Getenv("ENV") == server.STAGING_ENV {
		logger, err := zap.NewDevelopment()

		if err != nil {
			return nil, err
		}

		return logger, nil
	}

	logger, err := zap.NewProduction()

	if err != nil {
		return nil, err
	}

	return logger, nil
}
