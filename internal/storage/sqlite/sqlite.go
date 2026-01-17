package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage"

	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sql.DB
}

// New returns a new instance of the Storage.
func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"
	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.sqlite.SaveUser"
	stmt, err := s.db.Prepare("INSERT INTO users (email, pass_hash) VALUES (?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()
	result, err := stmt.ExecContext(ctx, email, passHash)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserAlreadyExists)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return result.LastInsertId()
}

func (s *Storage) User(ctx context.Context, email string) (*models.User, error) {
	const op = "storage.sqlite.GetUser"
	row := s.db.QueryRowContext(ctx, "SELECT id, email, pass_hash FROM users WHERE email = ?", email)
	var user models.User
	err := row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return &models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return &user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int) (bool, error) {
	const op = "storage.sqlite.IsAdmin"
	row := s.db.QueryRowContext(ctx, "SELECT is_admin FROM users WHERE id = ?", userID)
	var isAdmin bool
	err := row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, appID int) (*models.App, error) {
	const op = "storage.sqlite.App"
	row := s.db.QueryRowContext(ctx, "SELECT id, name, secret FROM apps WHERE id = ?", appID)
	var app models.App
	err := row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return &models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return &app, nil
}
