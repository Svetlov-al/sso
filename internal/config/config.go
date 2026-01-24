package config

import (
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env             string        `yaml:"env" env:"ENV" env-default:"local"`
	TokenTTL        time.Duration `yaml:"token_ttl" env:"TOKEN_TTL" env-default:"1h"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" env:"REFRESH_TOKEN_TTL" env-default:"720h"`
	Grpc            GRPCConfig    `yaml:"grpc"`
	Mongo           MongoConfig   `yaml:"mongo"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port" env:"GRPC_PORT" env-default:"50051"`
	Timeout time.Duration `yaml:"timeout" env:"GRPC_TIMEOUT" env-default:"10s"`
}

type MongoConfig struct {
	URI                 string `yaml:"uri" env:"MONGO_URI" env-default:"mongodb://localhost:27017"`
	Database            string `yaml:"database" env:"MONGO_DATABASE" env-default:"sso"`
	RefreshTokenPepper  string `yaml:"refresh_token_pepper" env:"REFRESH_TOKEN_PEPPER" env-default:"change-me-in-production"`
}

func LoadConfig(path string) *Config {
	var cfg Config

	if path != "" {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			panic("config file not found: " + path)
		}

		if err := cleanenv.ReadConfig(path, &cfg); err != nil {
			panic("failed to read config: " + err.Error())
		}
	} else {
		if err := cleanenv.ReadEnv(&cfg); err != nil {
			panic("failed to read env config: " + err.Error())
		}
	}

	return &cfg
}
