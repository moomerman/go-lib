package autocert

import (
	"fmt"
	"log"

	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/providers/dns/dnsmadeeasy"
)

// DNSProviderName holds the name of a provider
type DNSProviderName string

// DNSimpleProvider the DNSimple provider
// const DNSimpleProvider DNSProviderName = "dnsimple"

// DNSMadeEasyProvider the DNSMadeEasy provider
const DNSMadeEasyProvider DNSProviderName = "dnsmadeeasy"

// getDNSProvider returns an acme Provider for the given DNSProviderName
func getDNSProvider(name DNSProviderName, credentials []string) (challenge.Provider, error) {
	var err error
	var provider challenge.Provider

	switch name {
	case "dnsmadeeasy":
		config := dnsmadeeasy.NewDefaultConfig()
		config.BaseURL = "https://api.dnsmadeeasy.com/V2.0"
		config.APIKey = credentials[0]
		config.APISecret = credentials[1]
		provider, err = dnsmadeeasy.NewDNSProviderConfig(config)
	// case "dnsimple":
	// 	provider, err = dnsimple.NewDNSProviderCredentials(
	// 		credentials[0],
	// 		"",
	// 	)
	default:
		err = fmt.Errorf("Unrecognised DNS provider: %s", name)
	}

	return provider, err
}

// httpProvider holds the Request
type httpProvider struct {
	Manager *Manager
}

// Present prepares the domain for verification
func (p *httpProvider) Present(domain, token, keyAuth string) error {
	log.Println("[autocert]", "present", domain, token, keyAuth)
	return p.Manager.Store.Put(p.Manager.certChallengeCacheKey(domain), []byte(keyAuth))
}

// CleanUp cleans up after domain verification
func (p *httpProvider) CleanUp(domain, token, keyAuth string) error {
	log.Println("[autocert]", "cleanup", domain, token, keyAuth)
	return p.Manager.Store.Delete(p.Manager.certChallengeCacheKey(domain))
}
