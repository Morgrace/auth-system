package mailer

import (
	"testing"

	"github.com/Morgrace/auth-system/internal/config"
	"github.com/joho/godotenv"
)

// TestSendTestEmail sends a test email using the SMTP config from .env.
// Run with: go test -v -run TestSendTestEmail
func TestSendTestEmail(t *testing.T) {
	godotenv.Load("../../.env")
	cfg := config.Load()

	mailer := NewSMTPMailer(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SMTPUsername,
		cfg.SMTPPassword,
		cfg.SMTPFrom,
		cfg.ClientURL,
	)

	// CHANGE THIS to your own email address for testing
	testEmail := "mmorgrace@gmail.com"
	token := "test-token-123"

	err := mailer.SendVerificationEmail(testEmail, token)
	if err != nil {
		t.Fatalf("Failed to send test email: %v", err)
	}

	t.Log("Test email sent successfully. Check your inbox (and spam folder).")
}
