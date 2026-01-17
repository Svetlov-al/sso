package jwt

import (
	"sso/internal/domain/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(
	user *models.User,
	app *models.App,
	duration time.Duration,
) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"uid":    user.ID,
			"email":  user.Email,
			"exp":    time.Now().Add(duration).Unix(),
			"app_id": app.ID,
		})
	return token.SignedString([]byte(app.Secret))
}
