package autocert

import (
	"fmt"

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
