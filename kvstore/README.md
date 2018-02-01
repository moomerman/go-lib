# kvstore
The kvstore package provides an interface to a kvstore and multiple implementations.

https://godoc.org/github.com/moomerman/go-lib/kvstore

## Interface

```go
type Store interface {
	Get(key string) ([]byte, error)
	Put(key string, data []byte) error
	Delete(key string) error
}
```

## Implementations

* Dir - https://godoc.org/github.com/moomerman/go-lib/kvstore/dir
* Consul - https://godoc.org/github.com/moomerman/go-lib/kvstore/consul
* Etcd - https://godoc.org/github.com/moomerman/go-lib/kvstore/etcd
