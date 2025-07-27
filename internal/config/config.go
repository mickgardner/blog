package config

import (
	"os"
)

type Config struct {
	Env     string
	DBName  string
	Version string
}

func LoadConfig() Config {
	config := Config{
		Env:     os.Getenv("ENV"),
		DBName:  os.Getenv("DBNAME"),
		Version: os.Getenv("VERSION"),
	}
	return config
}
