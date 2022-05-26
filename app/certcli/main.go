package main

import (
	"fmt"
	"os"
)

type cliCommand func(command string, args []string)

func main() {
	args := os.Args[1:]
	usage := func() {
		fmt.Print(`certcli is a helpful CLI application to generate TLS artifacts, like root CA
certs, CSRs, client and server certs.
See the command listing below for more details.

Usage: certcli COMMAND [FLAGS]... [ARGS]...

COMMAND:
  root-ca   Generates a root, self-signed CA.
  cert-info View the details of a PEM or DER encoded certificate.
  csr       Generate a CSR with provided details.
  sign      Sign a CSR with a given CA cert and key and create a client cert, server cert, or sub-CA.
  format    Change the encoding of a certificate or private key between PEM and DER.

See each command's help text for more info.
`)
	}

	if len(args) == 0 {
		fmt.Println("No arguments specified")
		usage()
		os.Exit(1)
	}
	if args[0] == "--help" || args[0] == "-h" {
		usage()
		return
	}

	cmdMap := map[string]cliCommand{
		"root-ca":   cacert,
		"cert-info": certinfo,
		"csr":       createCsr,
		"sign":      sign,
		"format":    formatFile,
	}

	for command, fn := range cmdMap {
		if args[0] == command {
			fn(command, args[1:])
			return
		}
	}
	fmt.Printf("Unrecognized command '%s'\n", args[0])
	os.Exit(1)
}
