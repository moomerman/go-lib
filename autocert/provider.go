package autocert

import (
	"fmt"
	"log"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/dnsimple"
	"github.com/xenolf/lego/providers/dns/dnsmadeeasy"
)

// DNSProviderName holds the name of a provider
type DNSProviderName string

// DNSimpleProvider the DNSimple provider
const DNSimpleProvider DNSProviderName = "dnsimple"

// DNSMadeEasyProvider the DNSMadeEasy provider
const DNSMadeEasyProvider DNSProviderName = "dnsmadeeasy"

// GetDNSProvider returns an acme Provider for the given DNSProviderName
func GetDNSProvider(name DNSProviderName, credentials []string) (acme.ChallengeProvider, error) {
	var err error
	var provider acme.ChallengeProvider

	switch name {
	case "dnsmadeeasy":
		provider, err = dnsmadeeasy.NewDNSProviderCredentials(
			"https://api.dnsmadeeasy.com/V2.0",
			credentials[0],
			credentials[1],
		)
	case "dnsimple":
		provider, err = dnsimple.NewDNSProviderCredentials(
			credentials[0],
			"",
		)
	default:
		err = fmt.Errorf("Unrecognised DNS provider: %s", name)
	}

	return provider, err
}

// HTTPProvider holds the Request
type HTTPProvider struct {
	Request *Request
}

// Present prepares the domain for verification
func (p *HTTPProvider) Present(domain, token, keyAuth string) error {
	log.Println("[certs]", "present", domain, token, keyAuth)
	// p.Domain.SetChallenge(domain, keyAuth)
	return nil
}

// CleanUp cleans up after domain verification
func (p *HTTPProvider) CleanUp(domain, token, keyAuth string) error {
	log.Println("[certs]", "cleanup", domain, token, keyAuth)
	// p.Domain.RemoveChallenge(domain)
	return nil
}
