package config

import (
	"fmt"
	"os"
	"strconv"
)

type LaunchMode string

const (
	ProductionLaunchMode LaunchMode = "release"
	DebugLaunchMode      LaunchMode = "debug"
)

func (lm LaunchMode) IsValid() bool {
	return lm == ProductionLaunchMode || lm == DebugLaunchMode
}

func (lm LaunchMode) String() string {
	return string(lm)
}

func ParseLaunchMode(s string) (LaunchMode, error) {
	lm := LaunchMode(s)
	if !lm.IsValid() {
		return "", fmt.Errorf("invalid mode %q (want %q or %q)", s, ProductionLaunchMode, DebugLaunchMode)
	}
	return lm, nil
}

type ServerConfig struct {
	Port    string
	BaseUrl string
}

type DatabaseConnectionConfig struct {
	DbUrl    string
	User     string
	Password string
}

type RedisConfig struct {
	Addr     string
	Username string
	Password string
	Secret   string
	DB       int
}

type MailConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	From       string
	Encryption string // "tls", "ssl", or "none"
}

type Config struct {
	Mode         LaunchMode
	ServerArgs   ServerConfig
	DatabaseArgs DatabaseConnectionConfig
	RedisArgs    RedisConfig
	MailArgs     MailConfig
}

func GetEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}

	return fallback
}

func LoadConfig() (Config, error) {
	port := GetEnv("port", "8080")
	base_url := GetEnv("base_url", "localhost")
	mode, err := ParseLaunchMode(GetEnv("mode", "debug"))
	db_url := GetEnv("db_url", "localhost")

	if err != nil {
		fmt.Errorf("Failed to parse launch mode.")
		mode, _ = ParseLaunchMode("debug")
	}

	cfg := Config{
		Mode: mode,
		ServerArgs: ServerConfig{
			Port:    port,
			BaseUrl: base_url,
		},
		DatabaseArgs: DatabaseConnectionConfig{
			DbUrl:    db_url,
			User:     GetEnv("db_user", ""),
			Password: GetEnv("db_password", ""),
		},
		RedisArgs: RedisConfig{
			Addr:     GetEnv("redis_addr", "localhost:6379"),
			Username: GetEnv("redis_username", ""),
			Password: GetEnv("redis_password", ""),
			Secret:   os.Getenv("session_secret"),
			DB:       0,
		},
		MailArgs: MailConfig{
			Host:       GetEnv("mail_host", "localhost"),
			Port:       1025, // TODO: Mailpit default; override for production
			Username:   GetEnv("mail_username", ""),
			Password:   GetEnv("mail_password", ""),
			From:       GetEnv("mail_from", "noreply@hina.local"),
			Encryption: GetEnv("mail_encryption", "none"),
		},
	}

	if _, err := strconv.Atoi(port); err != nil {
		return Config{}, fmt.Errorf("PORT must be a number, got %q", port)
	}

	return cfg, nil
}
