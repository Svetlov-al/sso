package mongodb

import (
	"context"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Storage struct {
	client   *mongo.Client
	database *mongo.Database
	users    *mongo.Collection
	apps     *mongo.Collection
	counters *mongo.Collection
	tokens   *mongo.Collection
}

type userDoc struct {
	ID        int64     `bson:"_id"`
	Email     string    `bson:"email"`
	PassHash  []byte    `bson:"pass_hash"`
	Roles     []string  `bson:"roles"`
	CreatedAt time.Time `bson:"created_at"`
}

type appDoc struct {
	ID        int       `bson:"_id"`
	Name      string    `bson:"name"`
	Secret    string    `bson:"secret"`
	CreatedAt time.Time `bson:"created_at"`
}

type counterDoc struct {
	ID    string `bson:"_id"`
	Value int64  `bson:"value"`
}

type refreshTokenDoc struct {
	TokenHash      string     `bson:"token_hash"`
	UserID         int64      `bson:"user_id"`
	AppID          int        `bson:"app_id"`
	CreatedAt      time.Time  `bson:"created_at"`
	ExpiresAt      time.Time  `bson:"expires_at"`
	RevokedAt      *time.Time `bson:"revoked_at,omitempty"`
	ReplacedByHash *string    `bson:"replaced_by_hash,omitempty"`
}

// New creates a new MongoDB storage instance and sets up indexes.
func New(ctx context.Context, uri, database string) (*Storage, error) {
	const op = "storage.mongodb.New"

	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("%s: connect: %w", op, err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("%s: ping: %w", op, err)
	}

	db := client.Database(database)
	s := &Storage{
		client:   client,
		database: db,
		users:    db.Collection("users"),
		apps:     db.Collection("apps"),
		counters: db.Collection("counters"),
		tokens:   db.Collection("refresh_tokens"),
	}

	if err := s.ensureIndexes(ctx); err != nil {
		return nil, fmt.Errorf("%s: indexes: %w", op, err)
	}

	return s, nil
}

func (s *Storage) ensureIndexes(ctx context.Context) error {
	// users.email unique
	_, err := s.users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("users.email index: %w", err)
	}

	// apps.name unique
	_, err = s.apps.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "name", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("apps.name index: %w", err)
	}

	// apps.secret unique
	_, err = s.apps.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "secret", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("apps.secret index: %w", err)
	}

	// refresh_tokens.token_hash unique
	_, err = s.tokens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "token_hash", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("refresh_tokens.token_hash index: %w", err)
	}

	// refresh_tokens.expires_at TTL index (auto-delete expired tokens after 0 seconds past expiration)
	_, err = s.tokens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("refresh_tokens.expires_at TTL index: %w", err)
	}

	return nil
}

// Close disconnects from MongoDB.
func (s *Storage) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}

// nextID atomically increments and returns the next ID for a given collection.
func (s *Storage) nextID(ctx context.Context, collectionName string) (int64, error) {
	filter := bson.D{{Key: "_id", Value: collectionName}}
	update := bson.D{{Key: "$inc", Value: bson.D{{Key: "value", Value: int64(1)}}}}
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)

	var counter counterDoc
	err := s.counters.FindOneAndUpdate(ctx, filter, update, opts).Decode(&counter)
	if err != nil {
		return 0, err
	}
	return counter.Value, nil
}

// SaveUser saves a new user and returns the generated user ID.
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.mongodb.SaveUser"

	id, err := s.nextID(ctx, "users")
	if err != nil {
		return 0, fmt.Errorf("%s: nextID: %w", op, err)
	}

	doc := userDoc{
		ID:        id,
		Email:     email,
		PassHash:  passHash,
		Roles:     []string{},
		CreatedAt: time.Now(),
	}

	_, err = s.users.InsertOne(ctx, doc)
	if err != nil {
		if isDuplicateKeyError(err) {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserAlreadyExists)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// User retrieves a user by email.
func (s *Storage) User(ctx context.Context, email string) (*models.User, error) {
	const op = "storage.mongodb.User"

	var doc userDoc
	err := s.users.FindOne(ctx, bson.D{{Key: "email", Value: email}}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &models.User{
		ID:       doc.ID,
		Email:    doc.Email,
		PassHash: doc.PassHash,
		Roles:    doc.Roles,
	}, nil
}

// UserByID retrieves a user by ID.
func (s *Storage) UserByID(ctx context.Context, userID int64) (*models.User, error) {
	const op = "storage.mongodb.UserByID"

	var doc userDoc
	err := s.users.FindOne(ctx, bson.D{{Key: "_id", Value: userID}}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &models.User{
		ID:       doc.ID,
		Email:    doc.Email,
		PassHash: doc.PassHash,
		Roles:    doc.Roles,
	}, nil
}

// App retrieves an app by ID.
func (s *Storage) App(ctx context.Context, appID int) (*models.App, error) {
	const op = "storage.mongodb.App"

	var doc appDoc
	err := s.apps.FindOne(ctx, bson.D{{Key: "_id", Value: appID}}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &models.App{
		ID:     doc.ID,
		Name:   doc.Name,
		Secret: doc.Secret,
	}, nil
}

// SaveRefreshToken stores a new refresh token hash.
func (s *Storage) SaveRefreshToken(ctx context.Context, tokenHash string, userID int64, appID int, expiresAt time.Time) error {
	const op = "storage.mongodb.SaveRefreshToken"

	doc := refreshTokenDoc{
		TokenHash: tokenHash,
		UserID:    userID,
		AppID:     appID,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	_, err := s.tokens.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token by its hash.
func (s *Storage) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	const op = "storage.mongodb.GetRefreshToken"

	var doc refreshTokenDoc
	err := s.tokens.FindOne(ctx, bson.D{{Key: "token_hash", Value: tokenHash}}).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("%s: token not found", op)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &models.RefreshToken{
		TokenHash:      doc.TokenHash,
		UserID:         doc.UserID,
		AppID:          doc.AppID,
		CreatedAt:      doc.CreatedAt,
		ExpiresAt:      doc.ExpiresAt,
		RevokedAt:      doc.RevokedAt,
		ReplacedByHash: doc.ReplacedByHash,
	}, nil
}

// RotateRefreshToken revokes the old token and inserts a new one atomically.
func (s *Storage) RotateRefreshToken(ctx context.Context, oldHash, newHash string, userID int64, appID int, newExpiresAt time.Time) error {
	const op = "storage.mongodb.RotateRefreshToken"

	now := time.Now()

	// Revoke old token
	_, err := s.tokens.UpdateOne(ctx,
		bson.D{{Key: "token_hash", Value: oldHash}},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "revoked_at", Value: now},
				{Key: "replaced_by_hash", Value: newHash},
			}},
		},
	)
	if err != nil {
		return fmt.Errorf("%s: revoke old: %w", op, err)
	}

	// Insert new token
	newDoc := refreshTokenDoc{
		TokenHash: newHash,
		UserID:    userID,
		AppID:     appID,
		CreatedAt: now,
		ExpiresAt: newExpiresAt,
	}

	_, err = s.tokens.InsertOne(ctx, newDoc)
	if err != nil {
		return fmt.Errorf("%s: insert new: %w", op, err)
	}

	return nil
}

// SeedApp inserts an app if it doesn't exist (for dev/test).
func (s *Storage) SeedApp(ctx context.Context, id int, name, secret string) error {
	const op = "storage.mongodb.SeedApp"

	doc := appDoc{
		ID:        id,
		Name:      name,
		Secret:    secret,
		CreatedAt: time.Now(),
	}

	_, err := s.apps.InsertOne(ctx, doc)
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil // Already exists, skip
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// isDuplicateKeyError checks if the error is a MongoDB duplicate key error (code 11000).
func isDuplicateKeyError(err error) bool {
	var we mongo.WriteException
	if errors.As(err, &we) {
		for _, e := range we.WriteErrors {
			if e.Code == 11000 {
				return true
			}
		}
	}
	return false
}
