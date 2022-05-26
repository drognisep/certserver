package main

import (
	"fmt"
	"log"
	"os"
)

type cliCommand func(command string, args []string)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		log.Fatalln("No arguments specified")
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
