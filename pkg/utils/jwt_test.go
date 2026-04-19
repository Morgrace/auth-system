package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Morgrace/auth-system/internal/types"
	"github.com/golang-jwt/jwt/v5"

	"crypto/x509"
	"encoding/pem"
	"strings"
)

// setupTestJWTManager generates a fresh 2048-bit RSA key pair purely for testing.
// AppSec: We do this so CI/CD pipelines don't fail looking for a .env file.
func setupTestJWTManager(t *testing.T) *JWTManager {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return NewJWTManager(privateKey, &privateKey.PublicKey)
}

func TestGenerateAndVerifyToken(t *testing.T) {
	manager := setupTestJWTManager(t)
	userID := "user-123"
	role := types.RoleAdmin

	// Step 1: Generate the token
	tokenString, err := manager.GenerateToken(userID, role, 15*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if tokenString == "" {
		t.Fatalf("Expected token string, got empty string")
	}

	// Step 2: Verify the token
	claims, err := manager.VerifyToken(tokenString)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	// Step 3: Check the payload
	if claims.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, claims.UserID)
	}
	if claims.Role != role {
		t.Errorf("Expected Role %s, got %s", role, claims.Role)
	}
}

func TestVerifyTokenFailures(t *testing.T) {
	manager := setupTestJWTManager(t)
	hackerManager := setupTestJWTManager(t) // A completely separate keypair

	userID := "user-123"
	role := types.RoleUser

	// Create an expired token (expired 1 hour ago)
	expiredToken, _ := manager.GenerateToken(userID, role, -1*time.Hour)

	// Create a token signed by a different (hacker's) private key
	forgedToken, _ := hackerManager.GenerateToken(userID, "admin", 15*time.Minute)

	// Create a token using Symmetric HS256 to test algorithm downgrade prevention
	symmetricToken := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	})
	// Sign it with a random string pretending to be a secret
	downgradeTokenString, _ := symmetricToken.SignedString([]byte("hacker_secret"))

	tests := []struct {
		name        string
		tokenString string
	}{
		{
			name:        "Expired Token",
			tokenString: expiredToken,
		},
		{
			name:        "Forged Signature (Wrong RSA Key)",
			tokenString: forgedToken,
		},
		{
			name:        "Algorithm Downgrade Attack (HS256 instead of RS256)",
			tokenString: downgradeTokenString,
		},
		{
			name:        "Malformed Token String",
			tokenString: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.malformed.payload",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manager.VerifyToken(tc.tokenString)

			if err == nil {
				t.Errorf("CRITICAL: Expected VerifyToken to fail for '%s', but it succeeded", tc.name)
			}
		})
	}
}
func TestVerifyToken_MissingClaims(t *testing.T) {
	manager := setupTestJWTManager(t)

	// Create a token with no "sub" and no "role" using map claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		// intentionally omit "sub" and "role"
	})
	tokenString, err := token.SignedString(manager.privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	_, err = manager.VerifyToken(tokenString)
	if err == nil {
		t.Error("Expected error for missing claims, got nil")
	}
}

func TestParseKeysFromPEM(t *testing.T) {
	// Generate a real key pair (same as setupTestJWTManager)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert private key to PEM string (PKCS1 format for example)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	// Convert public key to PEM (PKIX format)
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Now simulate reading from .env: the PEM strings may have escaped newlines.
	// To be realistic, we could join them with literal "\n" and then replace.
	privStr := strings.ReplaceAll(string(privPEM), "\n", "\\n")
	pubStr := strings.ReplaceAll(string(pubPEM), "\n", "\\n")

	// In main, we would replace back
	parsedPriv, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(strings.ReplaceAll(privStr, "\\n", "\n")))
	if err != nil {
		t.Fatalf("Failed to parse private key from escaped PEM: %v", err)
	}
	parsedPub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(strings.ReplaceAll(pubStr, "\\n", "\n")))
	if err != nil {
		t.Fatalf("Failed to parse public key from escaped PEM: %v", err)
	}

	// Verify the parsed keys work by signing and verifying a token
	manager := NewJWTManager(parsedPriv, parsedPub)
	token, err := manager.GenerateToken("test", "user", time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken with parsed keys failed: %v", err)
	}
	claims, err := manager.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken with parsed keys failed: %v", err)
	}
	if claims.UserID != "test" {
		t.Errorf("Expected userID 'test', got %s", claims.UserID)
	}
}
