package business

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"text/template"
)

var (
	ErrNotACertificate = errors.New("the file is not in a known format or does not contain a certificate")
)

func ShowCertDetails(file string) error {
	cert, err := LoadCertFromFile(file)
	if err != nil {
		return err
	}
	if err := printCert(cert); err != nil {
		return err
	}

	return nil
}

func LoadCertFromFile(filepath string) (*x509.Certificate, error) {
	fileBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	blocks := decodePem(fileBytes)

	var cert *x509.Certificate
	for _, block := range blocks {
		var err error
		cert, err = decodeCert(block)
		if cert == nil || err != nil {
			continue
		}
		break
	}
	if cert == nil {
		return nil, ErrNotACertificate
	}
	return cert, nil
}

// This will effectively be a no-op if the input bytes are not PEM encoded.
func decodePem(fileBytes []byte) [][]byte {
	var blockBytes [][]byte
	block, rest := pem.Decode(fileBytes)
	if block == nil {
		return [][]byte{fileBytes}
	}

	blockBytes = [][]byte{block.Bytes}

	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blockBytes = append(blockBytes, block.Bytes)
	}

	return blockBytes
}

func decodeCert(derBytes []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

var (
	certTemplateText = `
Discovered {{if .IsCA }}CA{{else}}Server{{end}} cert
Common Name:     {{ .Subject.CommonName }}
S/N:             {{ .SerialNumber }}
SANs:            {{ .DNSNames }}
IPs:             {{ .IPAddresses }}

Effective:       {{ .NotBefore.String }}
Expiration:      {{ .NotAfter.String }}

Signature Algo:  {{ .SignatureAlgorithm.String }}
Signature:
{{ .SignatureString }}

Public Key Algo: {{ .PublicKeyAlgorithm.String }}
PublicKey:
{{ .PublicKeyString }}

Subject:
Common Name:         {{ .Subject.CommonName }}
Serial Number:       {{ .Subject.SerialNumber }}
Country:             {{ .Subject.Country }}
Organization:        {{ .Subject.Organization }}
Organizational Unit: {{ .Subject.OrganizationalUnit }}
Street Address:      {{ .Subject.StreetAddress }}
Locality:            {{ .Subject.Locality }}
Province:            {{ .Subject.Province }}
Postal Code:         {{ .Subject.PostalCode }}

Issuer: {{if .SelfSigned}}(Self-signed){{else}}
Common Name:         {{ .Issuer.CommonName }}
Serial Number:       {{ .Issuer.SerialNumber }}
Country:             {{ .Issuer.Country }}
Organization:        {{ .Issuer.Organization }}
Organizational Unit: {{ .Issuer.OrganizationalUnit }}
Street Address:      {{ .Issuer.StreetAddress }}
Locality:            {{ .Issuer.Locality }}
Province:            {{ .Issuer.Province }}
Postal Code:         {{ .Issuer.PostalCode }}{{end}}
`
	certTemplate = template.Must(template.New("cert-template").Parse(certTemplateText))
)

type certTemplateParams struct {
	*x509.Certificate
	SignatureString string
	PublicKeyString string
}

func printCert(cert *x509.Certificate) error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	pubKey := base64.StdEncoding.EncodeToString(pubKeyBytes)
	params := certTemplateParams{
		Certificate:     cert,
		SignatureString: base64.StdEncoding.EncodeToString(cert.Signature),
		PublicKeyString: pubKey,
	}
	var buf bytes.Buffer
	if err := certTemplate.Execute(&buf, &params); err != nil {
		return err
	}
	fmt.Println(buf.String())
	return nil
}

func (p *certTemplateParams) SelfSigned() bool {
	subject := p.Subject
	issuer := p.Issuer

	switch {
	case subject.CommonName != issuer.CommonName:
		return false
	case subject.SerialNumber != issuer.SerialNumber:
		return false
	default:
		return true
	}
}
