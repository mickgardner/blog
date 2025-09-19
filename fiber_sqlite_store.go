package main

import (
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/fiber/v2/utils"
	"gorm.io/gorm"
	"time"
)

// FiberSQLiteStore wraps our SQLiteStore to implement Fiber's Storage interface
type FiberSQLiteStore struct {
	store *SQLiteStore
}

// NewFiberSQLiteStore creates a new Fiber-compatible SQLite storage
func NewFiberSQLiteStore(sqliteStore *SQLiteStore) *FiberSQLiteStore {
	return &FiberSQLiteStore{
		store: sqliteStore,
	}
}

// Get retrieves value by key
func (s *FiberSQLiteStore) Get(key string) ([]byte, error) {
	if len(key) == 0 {
		return nil, nil
	}
	return s.store.Get(key)
}

// Set stores value with key and expiration time
func (s *FiberSQLiteStore) Set(key string, val []byte, exp time.Duration) error {
	if len(key) == 0 || len(val) == 0 {
		return nil
	}
	return s.store.Set(key, val, exp)
}

// Delete removes value by key
func (s *FiberSQLiteStore) Delete(key string) error {
	if len(key) == 0 {
		return nil
	}
	return s.store.Delete(key)
}

// Reset clears all storage
func (s *FiberSQLiteStore) Reset() error {
	return s.store.Reset()
}

// Close closes the storage
func (s *FiberSQLiteStore) Close() error {
	return s.store.Close()
}

// Conn is not implemented for SQLite storage
func (s *FiberSQLiteStore) Conn() interface{} {
	return s.store.db
}

// CreateFiberSQLiteStore is a helper function to create the Fiber session store config
func CreateFiberSQLiteStore(db *gorm.DB) *session.Store {
	// Create the SQLite store
	sqliteStore := NewSQLiteStore(db)

	// Wrap it for Fiber
	fiberStore := NewFiberSQLiteStore(sqliteStore)

	// Create the session store with our custom storage
	store := session.New(session.Config{
		Expiration:     24 * time.Hour,
		Storage:        fiberStore,
		KeyLookup:      "cookie:session_id",
		CookieSecure:   false, // Set to true in production with HTTPS
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		KeyGenerator:   utils.UUIDv4,
	})

	return store
}