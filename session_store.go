package main

import (
	"encoding/base64"
	"errors"
	"gorm.io/gorm"
	"time"
)

// Session model for database storage
type Session struct {
	ID        string `gorm:"primaryKey"`
	Data      string `gorm:"type:text"`
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SQLiteStore implements a session store using SQLite
type SQLiteStore struct {
	db         *gorm.DB
	gcInterval time.Duration
	stopGC     chan bool
}

// NewSQLiteStore creates a new SQLite session store
func NewSQLiteStore(db *gorm.DB) *SQLiteStore {
	store := &SQLiteStore{
		db:         db,
		gcInterval: 10 * time.Minute, // Run garbage collection every 10 minutes
		stopGC:     make(chan bool),
	}

	// Start garbage collection goroutine
	go store.gcLoop()

	return store
}

// Get retrieves session data by key
func (s *SQLiteStore) Get(key string) ([]byte, error) {
	var session Session
	err := s.db.Where("id = ? AND expires_at > ?", key, time.Now()).First(&session).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Session doesn't exist or expired
		}
		return nil, err
	}

	// Decode the base64 data
	data, err := base64.StdEncoding.DecodeString(session.Data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Set stores session data with expiration
func (s *SQLiteStore) Set(key string, data []byte, exp time.Duration) error {
	// Encode data as base64 for text storage
	encodedData := base64.StdEncoding.EncodeToString(data)

	expiresAt := time.Now().Add(exp)

	session := Session{
		ID:        key,
		Data:      encodedData,
		ExpiresAt: expiresAt,
	}

	// Use Upsert pattern - create or update
	err := s.db.Save(&session).Error
	return err
}

// Delete removes a session by key
func (s *SQLiteStore) Delete(key string) error {
	return s.db.Delete(&Session{}, "id = ?", key).Error
}

// Reset clears all sessions (use with caution)
func (s *SQLiteStore) Reset() error {
	return s.db.Exec("DELETE FROM sessions").Error
}

// Close stops the garbage collection routine
func (s *SQLiteStore) Close() error {
	s.stopGC <- true
	return nil
}

// gcLoop runs periodic garbage collection to remove expired sessions
func (s *SQLiteStore) gcLoop() {
	ticker := time.NewTicker(s.gcInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.gc()
		case <-s.stopGC:
			return
		}
	}
}

// gc removes expired sessions
func (s *SQLiteStore) gc() {
	err := s.db.Delete(&Session{}, "expires_at < ?", time.Now()).Error
	if err != nil {
		AppLogger.WithError(err).Warn("Failed to garbage collect expired sessions")
	}
}

// RunSessionGC performs immediate garbage collection (can be called manually)
func (s *SQLiteStore) RunSessionGC() error {
	result := s.db.Delete(&Session{}, "expires_at < ?", time.Now())
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected > 0 {
		AppLogger.WithField("count", result.RowsAffected).Info("Cleaned up expired sessions")
	}

	return nil
}