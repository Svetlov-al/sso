package tests

import (
	"sso/tests/suite"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	ssov1 "github.com/Svetlov-al/protos/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyAppID     = 0
	appID          = 1
	appSecret      = "test-secret"
	passDefaultLen = 10
)

func TestAuthRegisterLogin(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomPassword()

	respReq, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReq.GetUserId())

	loginResp, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)

	loginTime := time.Now()

	require.NotEmpty(t, loginResp.GetAccessToken())
	require.NotEmpty(t, loginResp.GetRefreshToken())

	tokenParsed, err := jwt.Parse(loginResp.GetAccessToken(), func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, tokenParsed)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))
	assert.Equal(t, respReq.GetUserId(), int64(claims["uid"].(float64)))

	// Check roles claim exists (should be empty array by default)
	roles, ok := claims["roles"].([]interface{})
	assert.True(t, ok)
	assert.Empty(t, roles)

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestAuthRefreshRotation(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomPassword()

	// Register user
	_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)

	// Login to get initial tokens
	loginResp, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.GetAccessToken())
	require.NotEmpty(t, loginResp.GetRefreshToken())

	refreshToken1 := loginResp.GetRefreshToken()

	// Use refresh token to get new tokens
	refreshResp, err := st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken1,
	})
	require.NoError(t, err)
	require.NotEmpty(t, refreshResp.GetAccessToken())
	require.NotEmpty(t, refreshResp.GetRefreshToken())

	refreshToken2 := refreshResp.GetRefreshToken()

	// Verify new tokens are different
	assert.NotEqual(t, refreshToken1, refreshToken2)

	// Try to use the old refresh token again (should fail - rotated/revoked)
	_, err = st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")

	// Use the new refresh token (should succeed)
	refreshResp2, err := st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, refreshResp2.GetAccessToken())
	require.NotEmpty(t, refreshResp2.GetRefreshToken())
}

func TestRefresh_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name         string
		refreshToken string
		expectedErr  string
	}{
		{
			name:         "Empty refresh token",
			refreshToken: "",
			expectedErr:  "refresh_token is required",
		},
		{
			name:         "Invalid refresh token",
			refreshToken: "invalid-token-that-does-not-exist",
			expectedErr:  "invalid refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
				RefreshToken: tt.refreshToken,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestRegisterLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	pass := randomPassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())

	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
	})
	require.Error(t, err)
	assert.Empty(t, respReg.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			expectedErr: "password is required",
		},
		{
			name:        "Register with Empty Email",
			email:       "",
			password:    randomPassword(),
			expectedErr: "email is required",
		},
		{
			name:        "Register with Both Empty",
			email:       "",
			password:    "",
			expectedErr: "email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Empty Email",
			email:       "",
			password:    randomPassword(),
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Both Empty Email and Password",
			email:       "",
			password:    "",
			appID:       appID,
			expectedErr: "email is required",
		},
		{
			name:        "Login with Non-Matching Password",
			email:       gofakeit.Email(),
			password:    randomPassword(),
			appID:       appID,
			expectedErr: "invalid email or password",
		},
		{
			name:        "Login without AppID",
			email:       gofakeit.Email(),
			password:    randomPassword(),
			appID:       emptyAppID,
			expectedErr: "app id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    gofakeit.Email(),
				Password: randomPassword(),
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func randomPassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
