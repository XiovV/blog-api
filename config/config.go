package config

import (
	"errors"
	"os"
	"strings"
)

type Config struct {
	PostgresDSN string
	Port        string
	Environment string
}

const (
	postgresEnv    = "POSTGRES_DSN"
	portEnv        = "PORT"
	environmentEnv = "ENV"
)

func New() (*Config, error) {
	postgres := os.Getenv(postgresEnv)
	port := os.Getenv(portEnv)
	environment := os.Getenv(environmentEnv)

	config := &Config{
		PostgresDSN: postgres,
		Port:        port,
		Environment: environment,
	}

	err := config.validate()
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) validate() error {
	envVars := []string{postgresEnv, portEnv, environmentEnv}

	missing := []string{}
	for _, env := range envVars {
		if val := os.Getenv(env); val == "" {
			missing = append(missing, env+" needs to be specified")
		}
	}

	if len(missing) > 0 {
		return errors.New(strings.Join(missing, "\n"))
	}

	return nil
}
