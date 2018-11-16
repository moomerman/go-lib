package autocert

import (
	"crypto/tls"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

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

	providerMu sync.Mutex
	provider   acme.ChallengeProvider

	ocspMu sync.Mutex
	ocsp   *ocsp.Response

	hostHash string

	lastErrorAt time.Time
	error       error
}
