package mailer

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
)

type SMTPMailer struct {
	host      string
	port      string
	username  string
	password  string
	from      string
	clientURL string
}

func NewSMTPMailer(host, port, username, password, from, clientURL string) *SMTPMailer {
	return &SMTPMailer{
		host:      host,
		port:      port,
		username:  username,
		password:  password,
		from:      from,
		clientURL: clientURL,
	}
}

func (m *SMTPMailer) SendVerificationEmail(to, token string) error {
	subject := "Verify Your Email Address"
	verifyURL := fmt.Sprintf("%s/api/v1/auth/verify-email?token=%s", m.clientURL, token)
	body := fmt.Sprintf(`
		<h1>Verify Your Email</h1>
		<p>Click the link below to verify your email address:</p>
		<a href="%s">%s</a>
		<p>This link expires in 24 hours.</p>
	`, verifyURL, verifyURL)

	return m.send(to, subject, body)
}

func (m *SMTPMailer) SendPasswordResetEmail(to, token string) error {
	subject := "Reset Your Password"
	resetURL := fmt.Sprintf("%s/api/v1/auth/reset-password/%s", m.clientURL, token)
	body := fmt.Sprintf(`
		<h1>Reset Your Password</h1>
		<p>Click the link below to reset your password:</p>
		<a href="%s">%s</a>
		<p>This link expires in 10 minutes.</p>
		<p>If you didn't request this, please ignore this email.</p>
	`, resetURL, resetURL)

	return m.send(to, subject, body)
}

func (m *SMTPMailer) send(to, subject, body string) error {
	addr := net.JoinHostPort(m.host, m.port)

	// Port 465 requires implicit TLS — connect with TLS first
	tlsConfig := &tls.Config{
		ServerName: m.host,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %w", err)
	}
	defer client.Close()

	auth := smtp.PlainAuth("", m.username, m.password, m.host)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP auth failed: %w", err)
	}

	if err = client.Mail(m.from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}

	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA failed: %w", err)
	}

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		m.from, to, subject, body,
	)

	if _, err = fmt.Fprint(w, msg); err != nil {
		return fmt.Errorf("SMTP write failed: %w", err)
	}

	if err = w.Close(); err != nil {
		return fmt.Errorf("SMTP close writer failed: %w", err)
	}

	log.Printf("Email sent to %s", to)
	return client.Quit()
}
