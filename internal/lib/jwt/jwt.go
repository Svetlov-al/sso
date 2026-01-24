package jwt

import (
	"fmt"
	"sso/internal/domain/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateToken creates an access JWT token with user claims including roles.
func GenerateToken(
	user *models.User,
	app *models.App,
	duration time.Duration,
) (string, error) {
	roles := user.Roles
	if roles == nil {
		roles = []string{}
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"uid":    user.ID,
			"email":  user.Email,
			"roles":  roles,
			"exp":    time.Now().Add(duration).Unix(),
			"app_id": app.ID,
		})
	return token.SignedString([]byte(app.Secret))
}

// ParseToken parses and validates a JWT token, returning the claims.
func ParseToken(tokenString string, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
