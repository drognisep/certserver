package main

import (
	"fmt"
	"github.com/drognisep/certserver/business"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
)

func sign(command string, args []string) {
	flags := pflag.NewFlagSet(command, pflag.ExitOnError)
	flags.Usage = func() {
		fmt.Printf(`'%[1]s' signs a Certificate Signing Request with a CA cert. This can be used to create sub-CAs.

Usage: %[1]s [FLAGS] CSR_FILE CA_CERT CA_KEY

CSR_FILE:
  The CSR file that should be signed by the CA.

CA_CERT:
  The CA's certificate.

CA_KEY:
  The CA key to use to sign the CSR.

Flags:
%s`, command, flags.FlagUsages())
	}

	var (
		isCA     bool
		isClient bool
		certOut  string
	)

	flags.BoolVar(&isCA, "is-ca", false, "Specifies that the output certificate should be for a CA")
	flags.BoolVar(&isClient, "is-client", false, "Specifies that the output certificate should be for client auth")
	flags.StringVar(&certOut, "cert-out", "", "Specifies a different output path for the certificate. Default is './<subject-common-name>.cer'.")

	if err := flags.Parse(args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if flags.NArg() < 3 {
		fmt.Println("Must pass CSR_FILE, CA_CERT, and CA_KEY arguments")
		flags.Usage()
		os.Exit(1)
	}

	if isCA && isClient {
		fmt.Println("Only one of 'is-ca' and 'is-client' may be specified")
		flags.Usage()
		os.Exit(1)
	}

	var certType business.CertType
	switch {
	case isCA:
		certType = business.CertTypeCA
	case isClient:
		certType = business.CertTypeClientAuth
	default:
		certType = business.CertTypeServerAuth
	}

	csrFile := flags.Arg(0)
	caCertFile := flags.Arg(1)
	caKeyFile := flags.Arg(2)

	cert, commonName, err := business.SignCsr(csrFile, caCertFile, caKeyFile, certType)
	if err != nil {
		fmt.Printf("Failed to create signed certificate: %v\n", err)
		os.Exit(1)
	}

	out := commonName + ".cer"
	if certOut != "" {
		out = certOut
	}
	if err := ioutil.WriteFile(out, cert, 0600); err != nil {
		fmt.Printf("Failed to write signed cert to '%s': %v\n", out, err)
		os.Exit(1)
	}
}
