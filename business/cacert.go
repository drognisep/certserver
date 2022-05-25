package business

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/google/uuid"
	"math/big"
	"net"
	"time"
)

const (
	PEM_CERTIFICATE     = "CERTIFICATE"
	PEM_RSA_PRIVATE_KEY = "RSA PRIVATE KEY"
)

type CaCertOpts struct {
	Name           pkix.Name
	ExpirationDate time.Time
	IpAddresses    []net.IP
	SANs           []string
	KeyBits        int
}

type CaCertOpt func(opts *CaCertOpts)

func CaExpirationMonths(months int) CaCertOpt {
	return func(opts *CaCertOpts) {
		opts.ExpirationDate = time.Now().AddDate(0, months, 0)
	}
}

func CaExpirationDays(days int) CaCertOpt {
	return func(opts *CaCertOpts) {
		opts.ExpirationDate = time.Now().AddDate(0, 0, days)
	}
}

func CaIpAddress(ip net.IP) CaCertOpt {
	return func(opts *CaCertOpts) {
		opts.IpAddresses = append(opts.IpAddresses, ip)
	}
}

func CaSubjectAlternativeName(name string) CaCertOpt {
	return func(opts *CaCertOpts) {
		opts.SANs = append(opts.SANs, name)
	}
}

func NewCaCert(commonName string, name pkix.Name, opts ...CaCertOpt) (cert []byte, key []byte, err error) {
	caOpts := CaCertOpts{
		Name:           name,
		ExpirationDate: time.Now().AddDate(0, 3, 0),
		KeyBits:        4096,
	}
	caOpts.Name.CommonName = commonName
	for _, opt := range opts {
		opt(&caOpts)
	}

	serial, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}
	caOpts.Name.SerialNumber = serial.String()

	caCert := x509.Certificate{
		SerialNumber:          serial,
		Subject:               caOpts.Name,
		NotBefore:             time.Now(),
		NotAfter:              caOpts.ExpirationDate,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              caOpts.SANs,
		IPAddresses:           caOpts.IpAddresses,
	}

	return generateCaCertAndKeys(err, caOpts.KeyBits, &caCert)
}

func generateSerialNumber() (*big.Int, error) {
	zeroInt := big.NewInt(0)
	serialUuid, err := uuid.NewRandom()
	if err != nil {
		return zeroInt, err
	}
	serialBytes, err := serialUuid.MarshalBinary()
	if err != nil {
		return zeroInt, err
	}
	var serial big.Int
	serial.SetBytes(serialBytes)
	return &serial, nil
}

func generateCaCertAndKeys(err error, keyBits int, template *x509.Certificate) ([]byte, []byte, error) {
	priv, err := generateRsaKeypair(keyBits)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)

	var pemCert bytes.Buffer
	err = pem.Encode(&pemCert, &pem.Block{
		Type:  PEM_CERTIFICATE,
		Bytes: cert,
	})
	if err != nil {
		return nil, nil, err
	}

	var pemKey bytes.Buffer
	err = pem.Encode(&pemKey, &pem.Block{
		Type:  PEM_RSA_PRIVATE_KEY,
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err != nil {
		return nil, nil, err
	}

	return pemCert.Bytes(), pemKey.Bytes(), nil
}

func generateRsaKeypair(keyBits int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	return priv, nil
}
