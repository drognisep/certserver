package business

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"time"
)

type csrOpts struct {
	name           pkix.Name
	expirationDate time.Time
	ipAddresses    []net.IP
	sans           []string
	keyBits        int
	isCA           bool
}

type CsrOpt func(opts *csrOpts)

func CsrAddIP(ip net.IP) CsrOpt {
	return func(opts *csrOpts) {
		opts.ipAddresses = append(opts.ipAddresses, ip)
	}
}

func CsrAddSan(san string) CsrOpt {
	return func(opts *csrOpts) {
		opts.sans = append(opts.sans, san)
	}
}

func NewGeneratedCsr(commonName string, name pkix.Name, opts ...CsrOpt) (csr []byte, priv []byte, err error) {
	_csrOpts := &csrOpts{
		name:    name,
		keyBits: 4096,
	}
	_csrOpts.name.CommonName = commonName

	for _, opt := range opts {
		opt(_csrOpts)
	}

	rsaPriv, err := generateRsaKeypair(_csrOpts.keyBits)
	if err != nil {
		return nil, nil, err
	}
	priv = x509.MarshalPKCS1PrivateKey(rsaPriv)

	csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     _csrOpts.name,
		IPAddresses: _csrOpts.ipAddresses,
		DNSNames:    _csrOpts.sans,
	}, rsaPriv)
	if err != nil {
		return nil, nil, err
	}
	return
}
