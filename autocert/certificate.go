package autocert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"path"
	"time"

	"github.com/moomerman/go-lib/kvstore"
	"github.com/xenolf/lego/acme"
)

// cert returns an existing certificate or requests a new one
func (m *Manager) cert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	req.certificateMu.Lock()
	defer req.certificateMu.Unlock()

	// aready loaded certificate, check expiry, renew if necessary and return
	if req.certificate != nil {
		if m.expiring(req.certificate) {
			log.Println("[autocert] checking to see if we have an updated certificate before renewing")
			cert, err := m.certFromStore(ctx, req)
			if err != nil {
				return nil, err
			}
			req.certificate = cert

			if m.expiring(req.certificate) {
				log.Println("[autocert] certificate has definitely expired, renewing")
				cert, err := m.renewCert(ctx, req)
				if err != nil {
					m.Notifier.error(req.Hosts, err.Error())
					return nil, err
				}
				m.Notifier.renewed(req.Hosts)
				req.certificate = cert
			}
		}
		if err := m.stapleOCSP(req, nil); err != nil {
			log.Println("[autocert]", "error with OCSP staple", err)
		}
		return req.certificate, nil
	}

	// fetch existing certificate from store if exists, check expiry, renew if necessay, return
	cert, err := m.certFromStore(ctx, req)
	if err != nil && err != kvstore.ErrCacheMiss {
		return nil, err
	}
	if err == nil {
		if m.expiring(cert) {
			cert, err = m.renewCert(ctx, req)
			if err != nil {
				m.Notifier.error(req.Hosts, err.Error())
				return nil, err
			}
			m.Notifier.renewed(req.Hosts)
		}
		req.certificate = cert
		if err := m.stapleOCSP(req, nil); err != nil {
			log.Println("[autocert]", "error with OCSP staple", err)
		}
		return cert, nil
	}

	// create a new certificate
	cert, err = m.createCert(ctx, req)
	if err != nil {
		m.Notifier.error(req.Hosts, err.Error())
		return nil, err
	}
	m.Notifier.created(req.Hosts)
	req.certificate = cert
	if err := m.stapleOCSP(req, nil); err != nil {
		log.Println("[autocert]", "error with OCSP staple", err)
	}
	return cert, nil
}

func (m *Manager) certFromStore(ctx context.Context, req *Request) (*tls.Certificate, error) {
	resource, err := m.certificateResourceFromStore(ctx, req)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (m *Manager) certificateResourceFromStore(ctx context.Context, req *Request) (*acme.CertificateResource, error) {
	certData, err := m.Store.Get(m.certCacheKey(req))
	if err != nil {
		return nil, err
	}
	pkData, err := m.Store.Get(m.certPKCacheKey(req))
	if err != nil {
		return nil, err
	}
	metaData, err := m.Store.Get(m.certMetaCacheKey(req))
	if err != nil {
		return nil, err
	}
	resource := &acme.CertificateResource{}
	if err := json.Unmarshal(metaData, resource); err != nil {
		return nil, err
	}
	resource.Certificate = certData
	resource.PrivateKey = pkData
	return resource, nil
}

func (m *Manager) putCertificateResourceInStore(ctd context.Context, req *Request, resource *acme.CertificateResource) error {
	meta, err := json.MarshalIndent(resource, "", "  ")
	if err != nil {
		return err
	}
	if err := m.Store.Put(m.certCacheKey(req), resource.Certificate); err != nil {
		return err
	}
	if err := m.Store.Put(m.certPKCacheKey(req), resource.PrivateKey); err != nil {
		return err
	}
	return m.Store.Put(m.certMetaCacheKey(req), meta)
}

// createCert creates a certificate and stores it or returns an error
func (m *Manager) createCert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	log.Println("[autocert] creating certificate", req.Hosts)
	if err := m.getLock(req.hostHash); err != nil {
		return nil, err
	}
	defer m.releaseLock(req.hostHash)
	user, err := m.user(ctx, req)
	if err != nil {
		return nil, err
	}
	client, err := m.client(ctx, req, user)
	if err != nil {
		return nil, err
	}
	resource, err := client.ObtainCertificate(req.Hosts, true, nil, true)
	if err != nil {
		log.Println("[autocert] error obtaining certificate", err)
		req.error = err
		return nil, err
	}
	if err := m.putCertificateResourceInStore(ctx, req, resource); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// renewCert renews a certificate and stores it or returns an error
// TODO: instead of using the first host as the key, use the hostHash (and maybe the first one to make it easier to debug)
func (m *Manager) renewCert(ctx context.Context, req *Request) (*tls.Certificate, error) {
	log.Println("[autocert] renewing certificate", req.Hosts)
	if err := m.getLock(req.hostHash); err != nil {
		return nil, err
	}
	defer m.releaseLock(req.hostHash)
	user, err := m.user(ctx, req)
	if err != nil {
		return nil, err
	}
	client, err := m.client(ctx, req, user)
	if err != nil {
		return nil, err
	}
	resource, err := m.certificateResourceFromStore(ctx, req)
	if err != nil {
		return nil, err
	}
	newResource, err := client.RenewCertificate(*resource, true, true)
	if err != nil {
		log.Println("[autocert] error renewing certificate", err)
		req.error = err
		return nil, err
	}
	if err := m.putCertificateResourceInStore(ctx, req, newResource); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(newResource.Certificate, newResource.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (m *Manager) certCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.hostHash, req.hostHash+".crt")
}

func (m *Manager) certPKCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.hostHash, req.hostHash+".key")
}

func (m *Manager) certMetaCacheKey(req *Request) string {
	return path.Join(m.cacheKeyPrefix(), req.hostHash, req.hostHash+".json")
}

func (m *Manager) certChallengeCacheKey(host string) string {
	return path.Join(m.cacheKeyPrefix(), "challenges", host+".auth")
}

func marshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var pemType string
	var keyBytes []byte
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		var err error
		pemType = "EC"
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		pemType = "RSA"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	}
	pemKey := pem.Block{Type: pemType + " PRIVATE KEY", Bytes: keyBytes}
	return pem.EncodeToMemory(&pemKey), nil
}

func unmarshalPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyBytes)
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}
	return nil, errors.New("unknown private key type")
}

func expiry(cert *tls.Certificate) (time.Time, error) {
	x, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Now(), err
	}
	return x.NotAfter, nil
}
