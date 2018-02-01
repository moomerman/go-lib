package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/moomerman/go-lib/autocert"
)

func main() {

	m := &autocert.Manager{
		Endpoint: "https://acme-staging.api.letsencrypt.org/directory",
		Cache:    autocert.DirCache("secret-dir"),
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

	go func() {
		if err := http.ListenAndServe(":8080", m.HTTPHandler(nil)); err != http.ErrServerClosed {
			log.Fatal("http server exited with error: ", err)
		}
	}()

	s := &http.Server{
		Addr:      ":4443",
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}

	if err := s.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatal("https server exited with error: ", err)
	}
}
