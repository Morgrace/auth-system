package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppEnv  string
	AppPort string

	// Database Configuration
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	// Cryptography & Tokens
	JWTPrivateKey      string
	JWTPublicKey       string
	JWTAccessTokenExp  time.Duration
	JWTRefreshTokenExp time.Duration

	// Server Resilence
	RateLimitPerMin int
	AllowedOrigins  []string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration

	// Mailer Configuration
	// SMTP Configuration
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	ClientURL string
}

// Load reads the environment variables and populates the Config struct.
func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}
	return &Config{
		AppEnv:  getEnv("APP_ENV", "development"),
		AppPort: getEnv("APP_PORT", "8080"),

		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnvOrPanic("DB_PASSWORD"),
		DBName:     getEnv("DB_NAME", "goauth"),

		// AppSec: Asymmetric RS256 keys mapped strictly
		JWTPrivateKey:      getEnvOrPanic("JWT_PRIVATE_KEY"),
		JWTPublicKey:       getEnvOrPanic("JWT_PUBLIC_KEY"),
		JWTAccessTokenExp:  parseDuration(getEnv("JWT_ACCESS_TOKEN_EXPIRY", "15m")),
		JWTRefreshTokenExp: parseDuration(getEnv("JWT_REFRESH_TOKEN_EXPIRY", "168h")),

		// Performance: Safe integer parsing preventing silent 0 values
		RateLimitPerMin: getEnvAsInt("RATE_LIMIT_PER_MIN", 100),
		AllowedOrigins:  parseOrigins(getEnv("ALLOWED_ORIGINS", "http://localhost:3000")),
		ReadTimeout:     time.Duration(getEnvAsInt("READ_TIMEOUT", 10)) * time.Second,
		WriteTimeout:    time.Duration(getEnvAsInt("WRITE_TIMEOUT", 10)) * time.Second,
		ShutdownTimeout: time.Duration(getEnvAsInt("SHUTDOWN_TIMEOUT", 10)) * time.Second,

		SMTPHost:     getEnvOrPanic("SMTP_HOST"),
		SMTPPort:     getEnv("SMTP_PORT", "587"),
		SMTPUsername: getEnvOrPanic("SMTP_USERNAME"),
		SMTPPassword: getEnvOrPanic("SMTP_PASSWORD"),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@yourapp.com"),
		ClientURL: getEnv("CLIENT_URL", "http://localhost:3000"),
	}
}

// getEnv returns the string value of an environment variable or a fallback
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	return fallback
}

// getEnvOrPanic enforces AppSec by crashing the app if a secret is missing.
func getEnvOrPanic(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		log.Fatalf("FATAL: Critical environment variable %s is missing", key)
	}
	return value
}

// getEnvAsInt safely parses integers and crashes on malformed data.
func getEnvAsInt(key string, fallback int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return fallback
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Fatalf("FATAL: Environment variable %s must be integer, got: %s", key, valueStr)
	}
	return value
}

// parseDuration converts string durations (e.g., "15m") to time.Duration safely.
func parseDuration(durationStr string) time.Duration {
	d, err := time.ParseDuration(durationStr)
	if err != nil {
		log.Fatalf("FATAL: Invalid time duration format: %s", durationStr)
	}
	return d
}

// parseOrigins splits a comma-separated string into a slice for CORS configurations.
func parseOrigins(originsStr string) []string {
	var origins []string
	for _, origin := range strings.Split(originsStr, ",") {
		cleaned := strings.TrimSpace(origin)
		if cleaned != "" {
			origins = append(origins, cleaned)
		}
	}
	return origins
}
