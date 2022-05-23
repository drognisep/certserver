package main

import (
	"fmt"
	"github.com/drognisep/certserver/business"
	"github.com/spf13/pflag"
	"os"
)

func certinfo(command string, args []string) {
	flags := pflag.NewFlagSet(command, pflag.ExitOnError)
	flags.Usage = func() {
		fmt.Printf(`'%[1]s' parses a PEM or DER encoded cert and displays the info. Requires a path argument pointing to a certificate file.

Usage: %[1]s FILE [FILE]...

FILE:
  A file containing a PEM or DER encoded certificate.`, command)
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
		if err := business.ShowCertDetails(path); err != nil {
			fmt.Printf("Failed to show certificate details: %v\n", err)
			os.Exit(1)
		}
	}
}
