package app

import (
	"context"
	"log/slog"
	"time"

	grpcapp "sso/internal/app/grpc"
	"sso/internal/config"
	"sso/internal/services/auth"
	"sso/internal/storage/mongodb"
)

type App struct {
	GRPCSrv *grpcapp.App
	storage *mongodb.Storage
}

func New(
	logger *slog.Logger,
	cfg *config.Config,
) *App {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := mongodb.New(ctx, cfg.Mongo.URI, cfg.Mongo.Database)
	if err != nil {
		panic(err)
	}

	authService := auth.New(
		logger,
		storage,
		storage,
		storage,
		storage,
		cfg.TokenTTL,
		cfg.RefreshTokenTTL,
		cfg.Mongo.RefreshTokenPepper,
	)
	grpcApp := grpcapp.New(logger, authService, cfg.Grpc.Port)

	return &App{
		GRPCSrv: grpcApp,
		storage: storage,
	}
}

func (a *App) Close(ctx context.Context) error {
	return a.storage.Close(ctx)
}
