package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/Morgrace/auth-system/internal/config"
	"github.com/golang-migrate/migrate/v4"

	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func New(cfg *config.Config) (*sql.DB, error) {

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)

	db, err := sql.Open("pgx", dsn)

	if err != nil {
		return nil, fmt.Errorf("Failed to open database connection: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(15 * time.Minute)

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("Failed to ping database: %w", err)
	}

	log.Println("Database connected successfully 🌐")
	return db, nil
}

func RunMigrations(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("Could not create migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://migrations", "postgres", driver)
	if err != nil {
		return fmt.Errorf("Could not initialize migrations: %w", err)
	}
	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("Could not run up migrations: %w", err)
	}
	log.Println("Database schema migrations applied successfully 🚀")

	return nil
}
