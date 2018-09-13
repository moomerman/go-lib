package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/moomerman/go-lib/autocert"
	"github.com/moomerman/go-lib/kvstore/dir"
)

func main() {
	m := &autocert.Manager{
		Endpoint: "https://acme-staging-v02.api.letsencrypt.org/directory",
		Store:    dir.Store("secret-dir"), // or consul.Store, etcd.Store
		Notifier: autocert.SlackNotifier("https://hooks.slack.com/services/..."),
		Prompt:   autocert.AcceptTOS,
		Email:    "moomerman@gmail.com",
	}

	// HTTP verification
	// m.Add(&autocert.Request{
	// 	Hosts: []string{"example.com", "www.example.com"},
	// })

	// DNS verification
	m.Add(&autocert.Request{
		Hosts:           []string{"letest.moocode.com"},
		DNSProviderName: autocert.DNSMadeEasyProvider,
		DNSCredentials:  []string{"36875f3e-c72a-464d-8c60-1da2647a6ef9", "3458659f-b53b-4f79-9297-39df7e89ba49"},
	})

	go func() {
		for {
			log.Println(m.Status())
			time.Sleep(5 * time.Second)
		}
	}()

	go http.ListenAndServe(":8080", m.HTTPHandler(nil))
	// m.Run() // optional blocking call to ensure all certificates are issued before starting https server
	// go m.Monitor() // optionally renew certificates in the background
	s := &http.Server{
		Addr:      ":4343",
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	s.ListenAndServeTLS("", "")
}
