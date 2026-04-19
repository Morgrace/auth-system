package mailer

import (
	"testing"
)

// TestSendTestEmail sends a test email using the SMTP config from .env.
// Run with: go test -v -run TestSendTestEmail
func TestSendTestEmail(t *testing.T) {

	mailer := NewSMTPMailer(
		"smtp-relay.brevo.com",
		"465",
		"a54c6c001@smtp-brevo.com",
		"xsmtpsib-57ee70a1b419663576af797dbd2462baa45c014ae8a96682642001d38f1aa1da-T2gLIJxpQcfQ3ZIi",
		"mmorgrace@gmail.com",
		"http://localhost:3000",
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
