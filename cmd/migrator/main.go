package main

import (
	"flag"
	"fmt"

	// Библиотека для работы с миграциями
	"github.com/golang-migrate/migrate/v4"
	// Драйвер для работы с SQLite
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	// Источник для работы с файлами
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var storagePath, migrationsPath, migrationsTable string
	flag.StringVar(&storagePath, "storage-path", "", "path to storage file")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to migrations directory")
	flag.StringVar(&migrationsTable, "migrations-table", "", "name of migrations table")
	flag.Parse()

	if storagePath == "" {
		panic("storage path is required")
	}

	if migrationsPath == "" {
		panic("migrations path is required")
	}

	m, err := migrate.New(
		"file://"+migrationsPath,
		fmt.Sprintf("sqlite3://%s?x-migrations-table=%s", storagePath, migrationsTable),
	)
	if err != nil {
		panic(err)
	}

	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			fmt.Println("no migrations to apply")
		} else {
			panic(err)
		}
		return
	}

	fmt.Println("migrations applied successfully")
}
