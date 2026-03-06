package utils

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewJWTManager(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) *JWTManager {
	return &JWTManager{
		privateKey: privKey,
		publicKey:  pubKey,
	}
}

type CustomClaims struct {
	UserID string `json:"sub"` // "sub" (Subject) is the RFC standard for the user's ID
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken signs a new JWT using the Private Key (RS256)
func (m *JWTManager) GenerateToken(userID string, role string, duration time.Duration) (string, error) {
	claims := CustomClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-system",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(m.privateKey)
}

// VerifyToken validates the RS256 signature using the Public Key
func (m *JWTManager) VerifyToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// 🔐 REQUIRED: Validate that essential claims are present
	if claims.UserID == "" {
		return nil, errors.New("missing user ID claim")
	}
	if claims.Role == "" {
		return nil, errors.New("missing role claim")
	}

	return claims, nil
}
