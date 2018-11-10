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
		DNSCredentials:  []string{"30f88aec-0a67-4787-9e58-192645db511a", "7175bbce-0c13-4ab0-b5b6-184f2149663f"},
	})

	// HTTP verification
	m.Add(&autocert.Request{
		Hosts: []string{"letest.moocode.com", "letest2.moocode.com"},
	})

	// m.RenewBefore = 2158 * time.Hour // 90 days, to force a renewal

	go func() {
		for {
			log.Printf("%+v\n", m.Status())
			time.Sleep(5 * time.Second)
		}
	}()

	go http.ListenAndServe(":8080", m.HTTPHandler(nil))
	// m.Run() // optional blocking call to ensure all certificates are issued before starting https server
	m.Monitor() // optionally renew certificates in the background
	s := &http.Server{
		Addr:      ":4343",
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	s.ListenAndServeTLS("", "")
}
