package main

import (
	"fmt"
	"github.com/drognisep/certserver/business"
	"github.com/spf13/pflag"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

func cacert(command string, args []string) {
	flags := pflag.NewFlagSet(command, pflag.ExitOnError)
	flags.Usage = func() {
		fmt.Printf(`'%[1]s' creates a new, self-signed root CA cert

Usage: %[1]s [FLAGS] COMMON_NAME

COMMON_NAME:
  The "CN" field in the certificate. This could be a domain name or another identifying string.
  If spaces are desired, ensure that they're escaped or grouped properly.

Flags:
%s`, command, flags.FlagUsages())
	}

	var (
		commonName   string
		caCertPath   string
		caKeyPath    string
		expireMonths int
		expireDays   int
		sans         []string
		ips          []net.IP
	)

	flags.StringVar(&caCertPath, "cert-out", "", "Specifies a different output path for the CA cert. Default is './<common-name>.cer'")
	flags.StringVar(&caKeyPath, "key-out", "", "Specifies a different output path for the CA key. Default is './<common-name>.key'")
	flags.IntVar(&expireMonths, "expire-months", 0, "Specifies the certificate's validity time, in months. This takes precedence over 'expire-days'")
	flags.IntVar(&expireDays, "expire-days", 0, "Specifies the certificate's validity time, in days.")
	flags.StringSliceVar(&sans, "san", nil, "Specifies a Subject Alternative Name used for this server cert")
	flags.IPSliceVar(&ips, "ip", nil, "Specifies an IP used for this server cert")
	if err := flags.Parse(args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if flags.NArg() < 1 {
		fmt.Println("Must pass the common name as an argument")
		os.Exit(1)
	}
	commonName = flags.Arg(0)

	if commonName == "" {
		fmt.Println("Common name is a required parameter")
		os.Exit(1)
	}
	commonName = strings.ReplaceAll(strings.TrimSpace(strings.ToLower(commonName)), " ", "")
	if caCertPath == "" {
		caCertPath = commonName + ".cer"
	}
	if caKeyPath == "" {
		caKeyPath = commonName + ".key"
	}

	var opts []business.CaCertOpt

	switch {
	case expireMonths > 0:
		opts = append(opts, business.CaExpirationMonths(expireMonths))
	case expireDays > 0:
		opts = append(opts, business.CaExpirationDays(expireDays))
	}

	for _, san := range sans {
		opts = append(opts, business.CaSubjectAlternativeName(san))
	}
	for _, ip := range ips {
		opts = append(opts, business.CaIpAddress(ip))
	}

	name, err := business.PromptCertNameDetails()
	if err != nil {
		fmt.Printf("Error prompting for certificate details: %v\n", err)
		os.Exit(1)
	}

	cert, key, err := business.NewCaCert(commonName, name, opts...)
	if err != nil {
		fmt.Printf("Error generating CA certificate: %v\n", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(caCertPath, cert, 0600); err != nil {
		fmt.Printf("Failed to write certificate to '%s': %v\n", caCertPath, err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(caKeyPath, key, 0600); err != nil {
		fmt.Printf("Failed to write key to '%s': %v\n", caKeyPath, err)
		os.Exit(1)
	}
}
