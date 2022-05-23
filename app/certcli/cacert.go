package main

import (
	"fmt"
	"github.com/drognisep/certserver/business"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"strings"
)

func cacert(args []string) {
	flags := pflag.NewFlagSet("ca-cert", pflag.ExitOnError)

	var (
		commonName   string
		caCertPath   string
		caKeyPath    string
		expireMonths int
		expireDays   int
	)

	flags.StringVar(&commonName, "common-name", "", "Specifies a common name for the new CA cert (required)")
	flags.StringVar(&caCertPath, "cert-out", "", "Specifies a different output path for the CA cert. Default is './<common-name>.cert'")
	flags.StringVar(&caKeyPath, "key-out", "", "Specifies a different output path for the CA key. Default is './<common-name>.key'")
	if err := flags.Parse(args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	if commonName == "" {
		fmt.Println("Common name is a required parameter")
		os.Exit(1)
	}
	commonName = strings.ReplaceAll(strings.TrimSpace(strings.ToLower(commonName)), " ", "")
	if caCertPath == "" {
		caCertPath = commonName + ".cert"
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
