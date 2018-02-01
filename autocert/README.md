# autocert
The autocert package provides automatic SSL certificate issuance & renewal from
LetsEncrypt (and any other ACME-based CA). It is intended to be used as a
drop-in library for go http servers.

The main motivation is to provide a closely-compatible `golang.org/x/crypto/acme/autocert`
library replacement that also handles DNS verification and will work well in
distributed environments.

The API is based strongly on the `golang.org/x/crypto/acme/autocert` package
so it can provide an easier transition.  The ACME implementation is provided
by the excellent `github.com/xenolf/lego` package.

## Usage

```go

// Using kvstore dir.Store, could also use consul.Store or etcd.Store
m := &autocert.Manager{
  Cache:    dir.Store("secret-dir"),
  Notifier: autocert.SlackNotifier("https://....."),
  Prompt:   autocert.AcceptTOS,
  Email:    "user@example.com",
}

// HTTP verification
m.Add(&autocert.Request{
  Hosts: []string{"example.com", "www.example.com"},
})

// DNS verification
m.Add(&autocert.Request{
  Hosts:           []string{"example.com"},
  DNSProviderName: autocert.DNSimpleProvider,
  DNSCredentials:  []string{"API_KEY"},
})

go http.ListenAndServe(":http", m.HTTPHandler(nil))
s := &http.Server{
  Addr:      ":https",
  TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
}
s.ListenAndServeTLS("", "")

// optionally monitor & renew certificates in the background
go m.Monitor()
```

