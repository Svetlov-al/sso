package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"sso/internal/config"
	"sso/internal/storage/mongodb"
)

func main() {
	var configPath string
	var seedApps bool
	flag.StringVar(&configPath, "config", "", "path to config file (or use CONFIG_PATH env)")
	flag.BoolVar(&seedApps, "seed", false, "seed test apps into database")
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv("CONFIG_PATH")
	}

	cfg := config.LoadConfig(configPath)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Connecting to MongoDB...")

	storage, err := mongodb.New(ctx, cfg.Mongo.URI, cfg.Mongo.Database)
	if err != nil {
		log.Fatalf("failed to connect to mongodb: %v", err)
	}
	defer storage.Close(ctx)

	log.Println("MongoDB connected, indexes created successfully")

	if seedApps {
		log.Println("Seeding test apps...")

		// Seed a default test app
		if err := storage.SeedApp(ctx, 1, "test", "test-secret"); err != nil {
			log.Fatalf("failed to seed test app: %v", err)
		}
		log.Println("Test app seeded (id=1, name=test)")

		// Seed a production app example
		if err := storage.SeedApp(ctx, 2, "production", "production-secret-change-me"); err != nil {
			log.Fatalf("failed to seed production app: %v", err)
		}
		log.Println("Production app seeded (id=2, name=production)")
	}

	fmt.Println("Database initialization completed successfully")
}
