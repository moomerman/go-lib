package autocert

import (
	"crypto/tls"
	"sync"

	"golang.org/x/crypto/acme"
)

// Request holds all the details required to request a certificate
type Request struct {
	Hosts           []string
	DNSProviderName DNSProviderName
	DNSCredentials  []string

	certificateMu sync.Mutex
	certificate   *tls.Certificate

	clientMu sync.Mutex
	client   *acme.Client
}
