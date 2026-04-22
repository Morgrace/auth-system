package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/Morgrace/auth-system/internal/config"
	"github.com/Morgrace/auth-system/internal/types"
	"github.com/Morgrace/auth-system/internal/user"
	"github.com/Morgrace/auth-system/pkg/utils"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
	"github.com/google/uuid"
)

type Mailer interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
}

type Service interface {
	Register(ctx context.Context, req RegisterRequest) (*user.MessageResponse, error)
	Login(ctx context.Context, req LoginRequest, deviceInfo, ipAddress string) (*AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string, deviceInfo, ipAddress string) (*AuthResponse, error)
	VerifyEmail(ctx context.Context, token string) (*user.MessageResponse, error)
	ResendVerification(ctx context.Context, req ResendVerificationRequest) (*user.MessageResponse, error)
	ForgotPassword(ctx context.Context, req ForgotPasswordRequest) (*user.MessageResponse, error)
	ResetPassword(ctx context.Context, token string, req ResetPasswordRequest) (*user.MessageResponse, error)
	Logout(ctx context.Context, refreshToken string) (*user.MessageResponse, error)
}

type service struct {
	userRepo   user.Repository
	authRepo   Repository
	jwtManager *utils.JWTManager
	mailer     Mailer
	cfg        *config.Config
}

func NewService(
	userRepo user.Repository,
	authRepo Repository,
	jwtManager *utils.JWTManager,
	mailer Mailer,
	cfg *config.Config,
) Service {
	return &service{
		userRepo:   userRepo,
		authRepo:   authRepo,
		jwtManager: jwtManager,
		mailer:     mailer,
		cfg:        cfg,
	}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func generateToken() (raw string, hashed string) {
	raw = uuid.New().String()
	hashed = hashToken(raw)
	return
}

func (s *service) Register(ctx context.Context, req RegisterRequest) (*user.MessageResponse, error) {
	existing, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("service: register check email: %w", err)
	}
	if existing != nil {
		return nil, appErrors.NewConflict("An account with this email already exists")
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("service: register hash password: %w", err)
	}

	rawToken, hashedToken := generateToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	now := time.Now()

	uid, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid: %w", err)
	}
	newUser := &user.User{
		ID:                       uid,
		FirstName:                req.FirstName,
		LastName:                 req.LastName,
		Email:                    req.Email,
		Role:                     types.RoleUser,
		IsEmailVerified:          false,
		EmailVerificationToken:   &hashedToken,
		EmailVerificationExpires: &expiresAt,
		PasswordHash:             hashedPassword,
		IsActive:                 true,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	created, err := s.userRepo.Create(ctx, newUser)
	if err != nil {
		return nil, fmt.Errorf("service: register create user: %w", err)
	}
	if err := s.mailer.SendVerificationEmail(created.Email, rawToken); err != nil {
		log.Printf("📧 service register send verification email failed: %v ", err)
	}
	return &user.MessageResponse{
		Message: "Registration successful. Please check your email to verify your account",
	}, nil
}

func (s *service) Login(ctx context.Context, req LoginRequest, deviceInfo, ipAddress string) (*AuthResponse, error) {
	u, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("service: login get user: %w", err)
	}
	if u == nil || !u.IsActive {
		return nil, appErrors.NewInvalidCredentials("Invalid email or password")
	}

	ok, err := utils.CheckPassword(req.Password, u.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("service: login check password: %w", err)
	}
	if !ok {
		return nil, appErrors.NewInvalidCredentials("Invalid email or password")
	}

	accessToken, err := s.jwtManager.GenerateToken(u.ID.String(), u.Role, s.cfg.JWTAccessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("service: login generate access token: %w", err)
	}

	rawRefresh, hashedRefresh := generateToken()
	refreshExp := time.Now().Add(s.cfg.JWTRefreshTokenExp)

	uid, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid: %w", err)
	}
	familyID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate family uuid: %w", err)
	}
	refreshToken := &RefreshToken{
		ID:         uid,
		UserID:     u.ID,
		TokenHash:  hashedRefresh,
		FamilyID:   familyID,
		DeviceInfo: &deviceInfo,
		IPAddress:  &ipAddress,
		ExpiresAt:  refreshExp,
		IsRevoked:  false,
		CreatedAt:  time.Now(),
	}
	if err := s.authRepo.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("service: login store refresh token: %w", err)
	}
	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		User:         user.ToUserResponse(u),
	}, nil
}

func (s *service) RefreshToken(ctx context.Context, refreshToken, deviceInfo, ipAddress string) (*AuthResponse, error) {
	hashed := hashToken(refreshToken)

	stored, err := s.authRepo.GetByTokenHash(ctx, hashed)
	if err != nil {
		return nil, fmt.Errorf("service: refresh token get: %w", err)
	}
	if stored == nil {
		return nil, appErrors.NewInvalidToken("Invalid or expired refresh token")
	}

	if stored.IsRevoked {
		if err := s.authRepo.RevokeFamily(ctx, stored.FamilyID); err != nil {
			log.Printf("service: failed to revoke family on reuse detection : %v", err)
		}
		return nil, appErrors.NewInvalidToken("Refresh token has already been used! Please login again.")
	}

	if stored.ExpiresAt.Before(time.Now()) {
		return nil, appErrors.NewExpiredToken("Refresh token has expired, please login again")
	}

	u, err := s.userRepo.GetByID(ctx, stored.UserID)
	if err != nil {
		return nil, fmt.Errorf("service: refresh token get user: %w", err)
	}
	if u == nil || !u.IsActive {
		return nil, appErrors.NewUnauthorized("User account is inactive or does not exist")
	}

	if err := s.authRepo.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("service: refresh token revoke old: %w", err)
	}

	rawNew, hashedNew := generateToken()
	newExp := time.Now().Add(s.cfg.JWTRefreshTokenExp)

	uid, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid: %w", err)
	}
	newToken := &RefreshToken{
		ID:         uid,
		UserID:     u.ID,
		TokenHash:  hashedNew,
		FamilyID:   stored.FamilyID,
		DeviceInfo: &deviceInfo,
		IPAddress:  &ipAddress,
		ExpiresAt:  newExp,
		IsRevoked:  false,
		CreatedAt:  time.Now(),
	}
	if err := s.authRepo.Create(ctx, newToken); err != nil {
		return nil, fmt.Errorf("service: refresh token create new: %w", err)
	}

	accessToken, err := s.jwtManager.GenerateToken(u.ID.String(), u.Role, s.cfg.JWTAccessTokenExp)
	if err != nil {
		return nil, fmt.Errorf("service: refresh token generate access: %w", err)
	}
	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: rawNew,
		User:         user.ToUserResponse(u),
	}, nil
}

func (s *service) VerifyEmail(ctx context.Context, token string) (*user.MessageResponse, error) {
	hashed := hashToken(token)
	u, err := s.userRepo.GetByEmailVerificationToken(ctx, hashed)
	if err != nil {
		return nil, fmt.Errorf("service: verify email get user: %w", err)
	}
	if u == nil || u.EmailVerificationExpires == nil || u.EmailVerificationExpires.Before(time.Now()) {
		return nil, appErrors.NewInvalidToken("Verification link is invalid or has expired")
	}
	u.IsEmailVerified = true
	u.EmailVerificationToken = nil
	u.EmailVerificationExpires = nil
	u.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("service: verify email update user: %w", err)
	}
	return &user.MessageResponse{Message: "Email verified successfully."}, nil
}

func (s *service) ResendVerification(ctx context.Context, req ResendVerificationRequest) (*user.MessageResponse, error) {
	u, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("service: resend verification get user: %w", err)
	}
	if u == nil || !u.IsActive {
		return &user.MessageResponse{Message: "If your email exists, a verification link has been sent."}, nil
	}
	if u.IsEmailVerified {
		return &user.MessageResponse{Message: "Email already verified."}, nil
	}
	rawToken, hashedToken := generateToken()
	expiresAt := time.Now().Add(24 * time.Hour)

	u.EmailVerificationToken = &hashedToken
	u.EmailVerificationExpires = &expiresAt
	u.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("service: resend verification update user: %w", err)
	}

	if err := s.mailer.SendVerificationEmail(u.Email, rawToken); err != nil {
		log.Printf("📧 service resend verification send email failed: %v", err)
	}
	return &user.MessageResponse{Message: "A verification link has been sent to your email address"}, nil
}

func (s *service) ForgotPassword(ctx context.Context, req ForgotPasswordRequest) (*user.MessageResponse, error) {
	u, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("service: forgot password get user: %w", err)
	}
	if u == nil || !u.IsActive {
		return &user.MessageResponse{Message: "A password reset link has been sent to your email address"}, nil
	}

	rawToken, hashedToken := generateToken()
	expiresAt := time.Now().Add(10 * time.Minute)

	u.PasswordResetToken = &hashedToken
	u.PasswordResetExpires = &expiresAt
	u.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("service: forgot password update user: %w", err)
	}

	if err := s.mailer.SendPasswordResetEmail(u.Email, rawToken); err != nil {
		log.Printf("service: 📧 forgot password send reset email failed: %v", err)
	}
	return &user.MessageResponse{Message: "A password reset link has been sent to your email address"}, nil
}

func (s *service) ResetPassword(ctx context.Context, token string, req ResetPasswordRequest) (*user.MessageResponse, error) {
	hashed := hashToken(token)
	u, err := s.userRepo.GetByPasswordResetToken(ctx, hashed)
	if err != nil {
		return nil, fmt.Errorf("service: reset password get user: %w", err)
	}
	if u == nil || u.PasswordResetExpires == nil || u.PasswordResetExpires.Before(time.Now()) {
		return nil, appErrors.NewInvalidToken("Password reset link is invalid or has expired")
	}

	newHash, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("service: reset password hash: %w", err)
	}

	now := time.Now()
	u.PasswordHash = newHash
	u.PasswordChangedAt = &now
	u.PasswordResetToken = nil
	u.PasswordResetExpires = nil
	u.UpdatedAt = now

	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("service: reset password update user: %w", err)
	}

	if err := s.authRepo.RevokeAllForUser(ctx, u.ID); err != nil {
		log.Printf("revoke refresh token failed: %v", err)
	}
	return &user.MessageResponse{Message: "Password has been reset successfully"}, nil
}

func (s *service) Logout(ctx context.Context, refreshToken string) (*user.MessageResponse, error) {
	hashed := hashToken(refreshToken)

	stored, err := s.authRepo.GetByTokenHash(ctx, hashed)
	if err != nil || stored == nil {
		return &user.MessageResponse{Message: "Logged out successfully"}, nil
	}

	if err := s.authRepo.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("service: logout revoke token: %w", err)
	}
	return &user.MessageResponse{Message: "Logged out successfully"}, nil
}
