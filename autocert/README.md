# autocert
The autocert package provides automatic SSL certificate issuance & renewal from
LetsEncrypt (and any other ACME-based CA). It is intended to be used as a
drop-in library for go http servers.

[Documentation](https://godoc.org/github.com/moomerman/go-lib/autocert)

The main motivation is to provide a closely-compatible [golang.org/x/crypto/acme/autocert](https://golang.org/x/crypto/acme/autocert)
library replacement that also handles DNS verification and will work well in
distributed environments.

The API is based strongly on the [golang.org/x/crypto/acme/autocert](https://golang.org/x/crypto/acme/autocert) package
so it can provide an easy transition.  The ACME implementation is provided
by the excellent [github.com/xenolf/lego](https://github.com/xenolf/lego) package.

## Usage

```go

m := &autocert.Manager{
  Endpoint: "https://acme-v02.api.letsencrypt.org/directory",
  Store:    dir.Store("secret-dir"), // or consul.Store, etcd.Store
  Notifier: autocert.SlackNotifier("https://hooks.slack.com/services/..."),
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
// m.Run() // optional blocking call to ensure all certificates are issued before starting https server
// go m.Monitor() // optionally renew certificates in the background
s := &http.Server{
  Addr:      ":https",
  TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
}
s.ListenAndServeTLS("", "")

```

