package autocert

import (
	"crypto/tls"
	"sync"

	"github.com/xenolf/lego/acme"
)

// Request holds all the details required to request a certificate
type Request struct {
	Hosts           []string
	DNSProviderName dnsProviderName
	DNSCredentials  []string

	certificateMu sync.Mutex
	certificate   *tls.Certificate

	clientMu sync.Mutex
	client   *acme.Client

	providerMu sync.Mutex
	provider   acme.ChallengeProvider

	hostHash string
}
