package etcd

import (
	"context"
	"sync"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/moomerman/go-lib/kvstore"
)

// Store implements kvstore.Store using a Etcd K/V store.
type Store struct {
	Endpoints []string

	clientMu sync.Mutex
	client   *clientv3.Client // initialized by etcdClient()
}

// Get implements kvstore.Store.Get
func (s *Store) Get(key string) ([]byte, error) {
	client, err := s.etcdClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	resp, err := client.Get(ctx, key)
	defer cancel()
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, kvstore.ErrCacheMiss
	}
	return resp.Kvs[0].Value, nil
}

// Put implements kvstore.Store.Put
func (s *Store) Put(key string, data []byte) error {
	client, err := s.etcdClient()
	if err != nil {
		return err
	}
	_, err = client.Put(context.Background(), key, string(data))
	return err
}

// Delete implements kvstore.Store.Delete
func (s *Store) Delete(key string) error {
	client, err := s.etcdClient()
	if err != nil {
		return err
	}
	_, err = client.Delete(context.Background(), key)
	return err
}

func (s *Store) etcdClient() (*clientv3.Client, error) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   s.Endpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	s.client = client
	return client, nil
}
