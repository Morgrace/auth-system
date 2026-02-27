package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	role := "admin"

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
	role := "user"

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
