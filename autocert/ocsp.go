package autocert

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"path"
	"time"

	"golang.org/x/crypto/ocsp"
)

func (m *Manager) stapleOCSP(request *Request, pemBundle []byte) error {
	// if we already have a valid ocsp in memory then skip the rest
	if request.ocsp != nil && freshOCSP(request.ocsp) {
		return nil
	}

	if pemBundle == nil {
		// The function in the acme package that gets OCSP requires a PEM-encoded cert
		bundle := new(bytes.Buffer)
		for _, derBytes := range request.certificate.Certificate {
			pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		}
		pemBundle = bundle.Bytes()
	}

	var ocspBytes []byte
	var ocspResp *ocsp.Response
	var ocspErr error
	var gotNewOCSP bool

	// try to load OCSP staple from storage and see if it is valid
	cachedOCSP, err := m.getCertOCSPFromStore(context.Background(), request)
	if err == nil {
		response, err := ocsp.ParseResponse(cachedOCSP, nil)
		if err != nil {
			return err
		}

		if freshOCSP(response) {
			log.Printf("[autocert] loaded OCSP is fresh for %v, %v\n", request.Hosts, response.NextUpdate)
			ocspBytes = cachedOCSP
			ocspResp = response
		}
	}

	if ocspResp == nil || len(ocspBytes) == 0 {
		log.Printf("[autocert] fetching new OCSP for %v\n", request.Hosts)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		user, err := m.user(ctx, request)
		if err != nil {
			return err
		}
		client, err := m.client(ctx, request, user)
		if err != nil {
			return err
		}
		ocspBytes, ocspResp, ocspErr = client.Certificate.GetOCSP(pemBundle)
		if ocspErr != nil {
			// An error here is not a problem because a certificate may simply
			// not contain a link to an OCSP server. But we should log it anyway.
			// There's nothing else we can do to get OCSP for this certificate,
			// so we can return here with the error.
			return fmt.Errorf("[autocert] no OCSP stapling for %v: %v", request.Hosts, ocspErr)
		}
		gotNewOCSP = true
	}

	if ocspResp.Status == ocsp.Good {
		// if ocspResp.NextUpdate.After(request.certificate.Leaf.NotAfter) {
		// 	// uh oh, this OCSP response expires AFTER the certificate does, that's kinda bogus.
		// 	// it was the reason a lot of Symantec-validated sites (not Caddy) went down
		// 	// in October 2017. https://twitter.com/mattiasgeniar/status/919432824708648961
		// 	return fmt.Errorf("invalid: OCSP response for %v valid after certificate expiration (%s)",
		// 		request.Hosts, request.certificate.Leaf.NotAfter.Sub(ocspResp.NextUpdate))
		// }
		request.certificate.OCSPStaple = ocspBytes
		request.ocsp = ocspResp
		if gotNewOCSP {
			return m.putCertOCSPInStore(context.Background(), request, ocspBytes)
		}
	}

	return nil
}

func (m *Manager) getCertOCSPFromStore(ctx context.Context, req *Request) ([]byte, error) {
	key := m.certOCSPCacheKey(req)
	log.Println("[autocert]", "loading OCSP from store", key)
	return m.Store.Get(key)
}

func (m *Manager) putCertOCSPInStore(ctx context.Context, req *Request, ocspBytes []byte) error {
	key := m.certOCSPCacheKey(req)
	log.Println("[autocert]", "putting OCSP in store", key)
	if err := m.getLock(key); err != nil {
		return err
	}
	defer m.releaseLock(key)
	if err := m.Store.Put(key, ocspBytes); err != nil {
		return err
	}
	return nil
}

func (m *Manager) certOCSPCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.hostHash, req.hostHash+".ocsp")
}

func freshOCSP(resp *ocsp.Response) bool {
	nextUpdate := resp.NextUpdate
	// If there is an OCSP responder certificate, and it expires before the
	// OCSP response, use its expiration date as the end of the OCSP
	// response's validity period.
	if resp.Certificate != nil && resp.Certificate.NotAfter.Before(nextUpdate) {
		nextUpdate = resp.Certificate.NotAfter
	}
	// start checking OCSP staple about halfway through validity period for good measure
	refreshTime := resp.ThisUpdate.Add(nextUpdate.Sub(resp.ThisUpdate) / 2)
	return time.Now().Before(refreshTime)
}
