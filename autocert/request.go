package autocert

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/lego"
	"golang.org/x/crypto/ocsp"
)

// Request holds all the details required to request a certificate
type Request struct {
	Hosts           []string
	DNSProviderName DNSProviderName
	DNSCredentials  []string

	certificateMu sync.Mutex
	certificate   *tls.Certificate

	clientMu sync.Mutex
	client   *lego.Client

	providerMu sync.Mutex
	provider   challenge.Provider

	ocspMu sync.Mutex
	ocsp   *ocsp.Response

	hostHash string

	lastErrorAt time.Time
	error       error
}
