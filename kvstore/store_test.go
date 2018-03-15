package kvstore_test

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/moomerman/go-lib/kvstore"
	"github.com/moomerman/go-lib/kvstore/consul"
	"github.com/moomerman/go-lib/kvstore/dir"
	"github.com/moomerman/go-lib/kvstore/etcd"
	"github.com/moomerman/go-lib/kvstore/s3"
)

func TestDirStore(t *testing.T) {
	store := dir.Store("testings")
	testStore(store, t)
}

func TestConsulStore(t *testing.T) {
	store := &consul.Store{
		Address: "localhost:8500",
		Scheme:  "http",
	}
	testStore(store, t)
}

func TestEtcdStore(t *testing.T) {
	store := &etcd.Store{
		Endpoints: []string{"localhost:2379"},
	}
	testStore(store, t)
}

func TestS3Store(t *testing.T) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	store := &s3.Store{
		Endpoint:    "minio.dev",
		AccessToken: "L5YDLJBB97WKDBIESOOQ",
		SecretToken: "tQMhEKy70wrBaY8iVWxv8HRKEWiFVu83KWMa8jjP",
		Bucket:      "kvstore",
		Region:      "us-west-2",
	}
	testStore(store, t)
}

func testStore(s kvstore.Store, t *testing.T) {
	key := "moo/testing.txt"
	content := []byte("hello")

	if err := s.Put(key, content); err != nil {
		t.Error(err)
	}

	res, err := s.Get(key)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(res, content) {
		t.Error("expected content to be equal")
	}

	if err := s.Delete(key); err != nil {
		t.Error(err)
	}

	res, err = s.Get(key)
	if err != kvstore.ErrCacheMiss {
		t.Error(err)
	}
	if res != nil {
		t.Error("expected nil")
	}
}
