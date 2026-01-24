package auth

import (
	"context"
	"errors"
	"sso/internal/domain/models"
	"sso/internal/services/auth"

	ssov1 "github.com/Svetlov-al/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	emptyValue = 0
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (accessToken, refreshToken string, err error)
	Register(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	Refresh(
		ctx context.Context,
		refreshToken string,
	) (newAccessToken, newRefreshToken string, err error)
	App(
		ctx context.Context,
		appID int,
	) (app *models.App, err error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	userID, err := s.auth.Register(
		ctx,
		req.GetEmail(),
		req.GetPassword(),
	)
	if err != nil {
		if errors.Is(err, auth.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &ssov1.RegisterResponse{
		UserId: int64(userID),
	}, nil
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "app id is required")
	}

	accessToken, refreshToken, err := s.auth.Login(
		ctx,
		req.GetEmail(),
		req.GetPassword(),
		int(req.GetAppId()),
	)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidAppID) {
			return nil, status.Error(codes.NotFound, "app not found")
		}
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *serverAPI) Refresh(
	ctx context.Context,
	req *ssov1.RefreshRequest,
) (*ssov1.RefreshResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	newAccessToken, newRefreshToken, err := s.auth.Refresh(
		ctx,
		req.GetRefreshToken(),
	)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}
		if errors.Is(err, auth.ErrRefreshTokenExpired) {
			return nil, status.Error(codes.Unauthenticated, "refresh token expired")
		}
		if errors.Is(err, auth.ErrRefreshTokenRevoked) {
			return nil, status.Error(codes.Unauthenticated, "refresh token revoked")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.RefreshResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
