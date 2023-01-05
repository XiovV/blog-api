package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	PostgresDSN  string `env:"POSTGRES_DSN" env-required:"true"`
	Port         string `env:"PORT" env-default:"8080"`
	Environment  string `env:"ENV" env-default:"PRODUCTION"`
	AESKey       string `env:"AES_KEY" env-required:"true"`
	SMTPHost     string `env:"SMTP_HOST" env-required:"true"`
	SMTPPort     int    `env:"SMTP_PORT" env-required:"true"`
	SMTPUsername string `env:"SMTP_USERNAME" env-required:"true"`
	SMTPPassword string `env:"SMTP_PASSWORD" env-required:"true"`
	SMTPSender   string `env:"SMTP_SENDER" env-required:"true"`
}

func New() (*Config, error) {
	var cfg Config

	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, err
}
