package main

import (
	"log"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		log.Fatalln("No arguments specified")
	}

	switch args[0] {
	case "ca-cert":
		cacert(args[1:])
	default:
		log.Fatalf("Unrecognized command '%s'\n", args[0])
	}
}
