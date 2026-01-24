package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sso/internal/app"
	"sso/internal/config"
	"sso/internal/lib/handlers/slogpretty"
	"syscall"
	"time"
)

const (
	envLocal = "local"
	envProd  = "prod"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config/local.yaml"
	}

	cfg := config.LoadConfig(configPath)
	logger := setupLogger(cfg.Env)
	logger.Info("starting sso server")

	application := app.New(logger, cfg)
	go application.GRPCSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	application.GRPCSrv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := application.Close(ctx); err != nil {
		logger.Error("failed to close application", slog.String("error", err.Error()))
	}

	logger.Info("shutting down sso server")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		log = setupPrettySlog()
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	default:
		panic("unknown environment: " + env)
	}
	return log
}

func setupPrettySlog() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}
	h := opts.NewPrettyHandler(os.Stdout)

	return slog.New(h)
}
