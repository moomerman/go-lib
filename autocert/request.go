package autocert

import (
	"crypto/tls"
	"sync"

	"github.com/xenolf/lego/acme"
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

func (r *Request) provider() (acme.ChallengeProvider, error) {
	if r.DNSProviderName != "" {
		return GetDNSProvider(r.DNSProviderName, r.DNSCredentials)
	}
	return &HTTPProvider{Request: r}, nil
}
