package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Morgrace/auth-system/internal/auth"
	"github.com/Morgrace/auth-system/internal/config"
	"github.com/Morgrace/auth-system/internal/dashboard"
	"github.com/Morgrace/auth-system/internal/database"
	"github.com/Morgrace/auth-system/internal/mailer"
	"github.com/Morgrace/auth-system/internal/middleware"
	"github.com/Morgrace/auth-system/internal/router"
	"github.com/Morgrace/auth-system/internal/user"
	"github.com/Morgrace/auth-system/pkg/utils"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	cfg := config.Load()

	db, err := database.New(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := database.RunMigrations(db.DB); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.JWTPrivateKey))
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.JWTPublicKey))
	if err != nil {
		log.Fatalf("Invalid public key: %v", err)
	}
	jwtmanager := utils.NewJWTManager(privKey, pubKey)

	// Repositories
	userRepo := user.NewRepository(db)
	authRepo := auth.NewRepository(db)

	// Mailer
	mailer := mailer.NewSMTPMailer(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.ClientURL)

	// Services
	authService := auth.NewService(userRepo, authRepo, jwtmanager, mailer, cfg)
	userService := user.NewService(userRepo, authRepo.RevokeAllForUser)

	//Handers
	authHandler := auth.NewHandler(authService)
	userHandler := user.NewHandler(userService)
	dashboardHandler := dashboard.NewHandler()

	// Middleware
	authMW := middleware.NewAuthMiddleware(jwtmanager)
	roleMW := middleware.NewRoleMiddleware()

	// Router
	r := router.New(authHandler, userHandler, dashboardHandler, authMW, roleMW)
	// Server with graceful shudown
	srv := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}
	go func() {
		log.Printf("🌐 Server starting on port %s", cfg.AppPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server ...🛑")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to Shutdown: %v", err)
	}
	log.Println("Server exited gracefully 😎")
}
