package main

import (
	"fmt"
	"github.com/drognisep/certserver/business"
	"github.com/spf13/pflag"
	"io/ioutil"
	"net"
	"os"
)

func createCsr(command string, args []string) {
	flags := pflag.NewFlagSet(command, pflag.ExitOnError)
	flags.Usage = func() {
		fmt.Printf(`'%[1]s' creates a new DER encoded Certificate Signing Request with the given details.

Usage: %[1]s [FLAGS] COMMON_NAME

COMMON_NAME:
  The "CN" field in the certificate. This could be a domain name or another identifying string.
  If spaces are desired, ensure that they're escaped or grouped properly.

Flags:
%s`, command, flags.FlagUsages())
	}

	var (
		commonName string
		csrPath    string
		keyPath    string
		sans       []string
		ips        []net.IP
		clientCert bool
	)

	flags.StringVar(&csrPath, "csr-out", "", "Specifies a different output path for the CSR. Default is './<common-name>.csr'.")
	flags.StringVar(&keyPath, "key-out", "", "Specifies a different output path for the private key. Default is './<common-name>.key'.")
	flags.StringSliceVar(&sans, "san", nil, "Specifies a Subject Alternative Name used for this CSR. At least one of 'san' or 'ip' must be specified, unless 'is-client' is specified.")
	flags.IPSliceVar(&ips, "ip", nil, "Specifies an IP used for this CSR. At least one of 'san' or 'ip' must be specified, unless 'is-client' is specified.")
	flags.BoolVar(&clientCert, "is-client", false, "Specifies that this CSR is for client authentication, so no SAN or IP will be allowed")
	if err := flags.Parse(args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if flags.NArg() < 1 {
		fmt.Println("Must pass the common name as an argument")
		flags.Usage()
		os.Exit(1)
	}
	commonName = flags.Arg(0)
	if csrPath == "" {
		csrPath = commonName + ".csr"
	}
	if keyPath == "" {
		keyPath = commonName + ".key"
	}
	if len(sans) == 0 && len(ips) == 0 && !clientCert {
		fmt.Println("At least one IP and/or SAN must be specified")
		flags.Usage()
		os.Exit(1)
	} else if clientCert && (len(sans) > 0 || len(ips) > 0) {
		fmt.Println("No SAN or IP is allowed for client authentication")
		flags.Usage()
		os.Exit(1)
	}

	var opts []business.CsrOpt

	for _, san := range sans {
		opts = append(opts, business.CsrAddSan(san))
	}
	for _, ip := range ips {
		opts = append(opts, business.CsrAddIP(ip))
	}

	name, err := business.PromptCertNameDetails()
	if err != nil {
		fmt.Printf("Error getting certificate details: %v\n", err)
		os.Exit(1)
	}

	csr, priv, err := business.NewGeneratedCsr(commonName, name, opts...)
	if err := ioutil.WriteFile(csrPath, csr, 0600); err != nil {
		fmt.Printf("Failed to write CSR to file '%s': %v\n", csrPath, err)
	}
	if err := ioutil.WriteFile(keyPath, priv, 0600); err != nil {
		fmt.Printf("Failed to write private key to file '%s': %v\n", keyPath, err)
	}
}
