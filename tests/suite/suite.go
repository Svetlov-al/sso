package suite

import (
	"context"
	"net"
	"sso/internal/config"
	"sso/internal/storage/mongodb"
	"strconv"
	"testing"
	"time"

	ssov1 "github.com/Svetlov-al/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	grpcHost  = "localhost"
	appID     = 1
	appName   = "test"
	appSecret = "test-secret"
)

type Suite struct {
	*testing.T
	Cfg        *config.Config
	AuthClient ssov1.AuthClient
	Storage    *mongodb.Storage
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.LoadConfig("../config/test.yaml")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	// Initialize MongoDB storage for test setup
	storage, err := mongodb.New(ctx, cfg.Mongo.URI, cfg.Mongo.Database)
	if err != nil {
		t.Fatalf("failed to connect to mongodb: %v", err)
	}

	// Seed test app
	if err := storage.SeedApp(ctx, appID, appName, appSecret); err != nil {
		t.Fatalf("failed to seed app: %v", err)
	}

	t.Cleanup(func() {
		t.Helper()
		cancel()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = storage.Close(cleanupCtx)
	})

	cc, err := grpc.NewClient(
		grpcAddress(cfg),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial grpc: %v", err)
	}

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: ssov1.NewAuthClient(cc),
		Storage:    storage,
	}
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(cfg.Grpc.Port))
}
