package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		log.Fatalln("No arguments specified")
	}

	cmdMap := map[string]func(string, []string){
		"ca-cert":   cacert,
		"cert-info": certinfo,
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
