package dir

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/moomerman/go-lib/kvstore"
)

// Store implements kvstore.Store using a directory on the local filesystem.
// If the directory does not exist, it will be created with 0700 permissions.
type Store string

// Get implements kvstore.Store.Get
func (s Store) Get(key string) ([]byte, error) {
	key = filepath.Join(string(s), key)
	data, err := ioutil.ReadFile(key)
	if os.IsNotExist(err) {
		return nil, kvstore.ErrCacheMiss
	}
	return data, err
}

// Put implements kvstore.Store.Put
func (s Store) Put(key string, data []byte) error {
	key = filepath.Join(string(s), key)
	if err := os.MkdirAll(filepath.Dir(key), 0700); err != nil {
		return err
	}
	return ioutil.WriteFile(key, data, 0600)
}

// Delete implements kvstore.Store.Delete
func (s Store) Delete(key string) error {
	key = filepath.Join(string(s), key)
	return os.Remove(key)
}
