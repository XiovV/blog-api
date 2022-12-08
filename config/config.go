package config

import (
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	PostgresDSN string `env:"POSTGRES_DSN" env-required:"true"`
	Port        string `env:"PORT" env-default:"8080"`
	Environment string `env:"ENV" env-default:"PRODUCTION"`
	AESKey      string `env:"AES_KEY" env-required:"true"`
}

func New() (*Config, error) {
	var cfg Config

	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		fmt.Println("err", err)
		return nil, err
	}

	return &cfg, err
}
