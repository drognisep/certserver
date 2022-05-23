package main

import (
	"fmt"
	"github.com/drognisep/certserver/business"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
)

func certinfo(args []string) {
	const commandName = "cert-info"
	flags := pflag.NewFlagSet(commandName, pflag.ExitOnError)
	flags.Usage = func() {
		fmt.Printf(`'%s' parses a PEM or DER encoded cert and displays the info. Requires a path argument pointing to a certificate file.

Flags:
%s`, commandName, flags.FlagUsages())
	}
	if err := flags.Parse(args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if flags.NArg() < 1 {
		fmt.Println("Need at least 1 path argument pointing to a certificate file")
		os.Exit(1)
	}
	paths := flags.Args()
	for _, path := range paths {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Printf("Failed to read file '%s': %v\n", path, err)
			os.Exit(1)
		}
		if err := business.ShowCertDetails(data); err != nil {
			fmt.Printf("Failed to parse certificate: %v\n", err)
			os.Exit(1)
		}
	}
}
