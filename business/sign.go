package business

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"time"
)

type CertType int

const (
	CertTypeServerAuth CertType = iota
	CertTypeCA
	CertTypeClientAuth
)

func SignCsr(csrFile, caCertFile, caKeyFile string, certType CertType) ([]byte, string, error) {
	csrFileBytes, err := ioutil.ReadFile(csrFile)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read CSR file '%s': %w", csrFile, err)
	}
	caCertBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read CA certificate '%s': %w", caCertFile, err)
	}
	caKeyBytes, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read CA key '%s': %w", caKeyFile, err)
	}

	csr, err := x509.ParseCertificateRequest(csrFileBytes)
	if err != nil {
		return nil, "", err
	}
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, "", err
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBytes)
	if err != nil {
		return nil, "", err
	}

	if !caCert.IsCA {
		return nil, "", fmt.Errorf("file '%s' is not a CA cert", caCertFile)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("error checking CSR signature: %w", err)
	}

	serial, err := generateSerialNumber()
	if err != nil {
		return nil, "", err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now(),
	}
	template.Subject.SerialNumber = serial.String()

	switch certType {
	case CertTypeServerAuth:
		template.NotAfter = time.Now().AddDate(0, 3, 0)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	case CertTypeClientAuth:
		template.NotAfter = time.Now().AddDate(0, 0, 30)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case CertTypeCA:
		template.NotAfter = time.Now().AddDate(0, 6, 0)
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	default:
		return nil, "", errors.New("unknown certificate type")
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, "", err
	}

	newCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, "", err
	}
	if err := newCert.CheckSignatureFrom(caCert); err != nil {
		return nil, "", fmt.Errorf("unable to verify CA signature: %w", err)
	}

	return cert, newCert.Subject.CommonName, nil
}
