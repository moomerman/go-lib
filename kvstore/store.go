package kvstore

import (
	"errors"
)

// ErrCacheMiss is returned when a key is not found in the store
var ErrCacheMiss = errors.New("kvstore: cache miss")

// Store is used by Manager to store and retrieve data
type Store interface {
	// Get returns a certificate data for the specified key or error.
	// If there's no such key in the store ErrCacheMiss will be returned
	Get(key string) ([]byte, error)

	// Put stores the data in the store under the specified key.
	// Underlying implementations may use any data storage format,
	// as long as the reverse operation, Get, results in the original data.
	Put(key string, data []byte) error

	// Delete removes data from the store under the specified key.
	// If there's no such key in the store, Delete returns nil.
	Delete(key string) error
}
