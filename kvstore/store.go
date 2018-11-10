package kvstore

import (
	"errors"
	"os"
)

// ErrCacheMiss is returned when a key is not found in the store
var ErrCacheMiss = errors.New("kvstore: cache miss")

// Store provides an interface for operations on a KV store
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

// GetLock attempts to get a lock for the key in the given store
func GetLock(store Store, key string) error {
	key = key + ".lock"
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	data, err := store.Get(key)
	if err != nil && err != ErrCacheMiss {
		return err
	}
	if err == nil && string(data) != hostname {
		return errors.New("unable to obtain lock, owned by: " + string(data))
	}
	if err := store.Put(key, []byte(hostname)); err != nil {
		return err
	}
	data, err = store.Get(key)
	if err != nil && err != ErrCacheMiss {
		return err
	}
	if err == nil && string(data) != hostname {
		return errors.New("unable to obtain lock, owned by: " + string(data))
	}

	// TODO: optional timer to release the lock
	return nil
}

// ReleaseLock releases the lock for the key in the given store
func ReleaseLock(store Store, key string) error {
	key = key + ".lock"
	return store.Delete(key)
}
