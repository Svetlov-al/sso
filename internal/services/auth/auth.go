package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/sl"
	"sso/internal/storage"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	logger          *slog.Logger
	userSaver       UserSaver
	userProvider    UserProvider
	appProvider     AppProvider
	tokenProvider   RefreshTokenProvider
	tokenTTL        time.Duration
	refreshTokenTTL time.Duration
	refreshPepper   string
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(
		ctx context.Context,
		email string,
	) (user *models.User, err error)
	UserByID(
		ctx context.Context,
		userID int64,
	) (user *models.User, err error)
}

type AppProvider interface {
	App(
		ctx context.Context,
		appID int,
	) (app *models.App, err error)
}

type RefreshTokenProvider interface {
	SaveRefreshToken(ctx context.Context, tokenHash string, userID int64, appID int, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldHash, newHash string, userID int64, appID int, newExpiresAt time.Time) error
}

var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrInvalidAppID         = errors.New("invalid app ID")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrInvalidRefreshToken  = errors.New("invalid refresh token")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenRevoked  = errors.New("refresh token revoked")
)

// New returns a new instance of the Auth service.
func New(
	logger *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenProvider RefreshTokenProvider,
	tokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	refreshPepper string,
) *Auth {
	return &Auth{
		userSaver:       userSaver,
		userProvider:    userProvider,
		logger:          logger,
		appProvider:     appProvider,
		tokenProvider:   tokenProvider,
		tokenTTL:        tokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		refreshPepper:   refreshPepper,
	}
}

func (a *Auth) Register(
	ctx context.Context,
	email string,
	password string,
) (userID int64, err error) {
	const op = "auth.Register"
	log := a.logger.With(
		slog.String("op", op),
		slog.String("email", email),
	)
	log.Info("register request", slog.String("email", email))

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userID, err = a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserAlreadyExists) {
			log.Warn("user already exists", sl.Err(err))
			return 0, fmt.Errorf("%s: %w", op, ErrUserAlreadyExists)
		}
		log.Error("failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered", slog.Int64("userID", userID))

	return userID, nil
}

// Login authenticates user and returns access token and refresh token.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (accessToken, refreshToken string, err error) {
	const op = "auth.Login"
	log := a.logger.With(slog.String("op", op))
	log.Info("login request", slog.String("email", email), slog.Int("appID", appID))

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		log.Error("failed to get user", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Warn("invalid password", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))
			return "", "", fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}
		log.Error("failed to get app", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info(
		"user logged in",
		slog.Int64("userID", user.ID),
		slog.String("appName", app.Name),
	)

	accessToken, err = jwt.GenerateToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate access token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refreshToken, err = a.generateAndSaveRefreshToken(ctx, user.ID, appID)
	if err != nil {
		log.Error("failed to generate refresh token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

// Refresh exchanges a valid refresh token for a new access token and refresh token (rotation).
func (a *Auth) Refresh(
	ctx context.Context,
	refreshToken string,
) (newAccessToken, newRefreshToken string, err error) {
	const op = "auth.Refresh"
	log := a.logger.With(slog.String("op", op))
	log.Info("refresh request")

	tokenHash := a.hashRefreshToken(refreshToken)

	tokenDoc, err := a.tokenProvider.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		log.Warn("refresh token not found", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	// Check if token is revoked
	if tokenDoc.RevokedAt != nil {
		log.Warn("refresh token already revoked")
		return "", "", fmt.Errorf("%s: %w", op, ErrRefreshTokenRevoked)
	}

	// Check if token is expired
	if time.Now().After(tokenDoc.ExpiresAt) {
		log.Warn("refresh token expired")
		return "", "", fmt.Errorf("%s: %w", op, ErrRefreshTokenExpired)
	}

	// Get user and app
	user, err := a.userProvider.UserByID(ctx, tokenDoc.UserID)
	if err != nil {
		log.Error("failed to get user", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	app, err := a.appProvider.App(ctx, tokenDoc.AppID)
	if err != nil {
		log.Error("failed to get app", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// Generate new access token
	newAccessToken, err = jwt.GenerateToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate access token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// Generate new refresh token and rotate
	newRefreshTokenRaw, err := generateRefreshTokenRaw()
	if err != nil {
		log.Error("failed to generate refresh token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	newHash := a.hashRefreshToken(newRefreshTokenRaw)
	newExpiresAt := time.Now().Add(a.refreshTokenTTL)

	err = a.tokenProvider.RotateRefreshToken(ctx, tokenHash, newHash, tokenDoc.UserID, tokenDoc.AppID, newExpiresAt)
	if err != nil {
		log.Error("failed to rotate refresh token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("tokens refreshed", slog.Int64("userID", user.ID))

	return newAccessToken, newRefreshTokenRaw, nil
}

func (a *Auth) App(
	ctx context.Context,
	appID int,
) (app *models.App, err error) {
	const op = "auth.App"
	log := a.logger.With(slog.String("op", op), slog.Int("appID", appID))
	log.Info("app request", slog.Int("appID", appID))

	app, err = a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))
			return nil, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}
		log.Error("failed to get app", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("app found", slog.String("appName", app.Name))

	return app, nil
}

// generateAndSaveRefreshToken creates a new refresh token, stores its hash, and returns the raw token.
func (a *Auth) generateAndSaveRefreshToken(ctx context.Context, userID int64, appID int) (string, error) {
	rawToken, err := generateRefreshTokenRaw()
	if err != nil {
		return "", err
	}

	tokenHash := a.hashRefreshToken(rawToken)
	expiresAt := time.Now().Add(a.refreshTokenTTL)

	if err := a.tokenProvider.SaveRefreshToken(ctx, tokenHash, userID, appID, expiresAt); err != nil {
		return "", err
	}

	return rawToken, nil
}

// hashRefreshToken computes SHA-256 hash of the token with pepper.
func (a *Auth) hashRefreshToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token + a.refreshPepper))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// generateRefreshTokenRaw generates a cryptographically secure random token.
func generateRefreshTokenRaw() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
