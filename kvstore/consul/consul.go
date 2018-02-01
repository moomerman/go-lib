package consul

import (
	"sync"

	"github.com/hashicorp/consul/api"
	"github.com/moomerman/go-lib/kvstore"
)

// Store implements kvstore.Store using a Consul K/V store.
type Store struct {
	Address string
	Scheme  string
	Token   string

	clientMu sync.Mutex
	client   *api.Client // initialized by the client method
}

// Get implements kvstore.Store.Get
func (s *Store) Get(key string) ([]byte, error) {
	client, err := s.consul()
	if err != nil {
		return nil, err
	}

	pair, _, err := client.KV().Get(key, nil)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, kvstore.ErrCacheMiss
	}
	return pair.Value, nil
}

// Put implements kvstore.Store.Put
func (s *Store) Put(key string, data []byte) error {
	client, err := s.consul()
	if err != nil {
		return err
	}

	pair := &api.KVPair{Key: key, Value: data}
	_, err = client.KV().Put(pair, nil)
	return err
}

// Delete implements kvstore.Store.Delete
func (s *Store) Delete(key string) error {
	client, err := s.consul()
	if err != nil {
		return err
	}

	_, err = client.KV().Delete(key, nil)
	return err
}

func (s *Store) consul() (*api.Client, error) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	cfg := &api.Config{Address: s.Address, Scheme: s.Scheme, Token: s.Token}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	_, err = client.Status().Leader()
	if err != nil {
		return nil, err
	}
	s.client = client
	return s.client, nil
}
