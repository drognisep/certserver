package main

import (
	"errors"
	"fmt"
	"github.com/drognisep/certserver/business/format"
	"github.com/spf13/pflag"
	"os"
	"strings"
)

func formatFile(command string, args []string) {
	flags := pflag.NewFlagSet(command, pflag.ExitOnError)
	flags.Usage = func() {
		fmt.Printf(`'%[1]s' changes a certificate to another supported format.

Usage: %[1]s [FLAGS]... TYPE IN_FILE OUT_FILE

TYPE:
  The type of file to format. May be one of 'cert' or 'private_key'.

IN_FILE:
  The file to use as input.

OUT_FILE:
  The file to use to output the result.

Flags:
%s`, command, flags.FlagUsages())
	}

	var (
		sourceFormat format.Encoding
		targetFormat format.Encoding
	)

	flags.Bool("from-der", false, "Specifies that the source format is DER")
	flags.Bool("from-pem", false, "Specifies that the source format is PEM")
	flags.Bool("to-der", false, "Specifies that the target format is DER")
	flags.Bool("to-pem", false, "Specifies that the target format is PEM")
	if err := flags.Parse(args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	flags.Visit(func(flag *pflag.Flag) {
		switch flag.Name {
		case "from-der":
			sourceFormat = format.EncodingDer
		case "from-pem":
			sourceFormat = format.EncodingPem
		case "to-der":
			targetFormat = format.EncodingDer
		case "to-pem":
			targetFormat = format.EncodingPem
		}
	})

	if sourceFormat == 0 {
		fmt.Println("Must specify a source format")
		flags.Usage()
		os.Exit(1)
	}
	if targetFormat == 0 {
		fmt.Println("Must specify a target format")
		flags.Usage()
		os.Exit(1)
	}

	if sourceFormat == targetFormat {
		fmt.Println("Formats are the same, exiting")
		os.Exit(0)
	}

	if flags.NArg() < 3 {
		fmt.Println("Must specify TYPE, IN_FILE, and OUT_FILE")
		flags.Usage()
		os.Exit(1)
	}
	typeArg, inArg, outArg := flags.Arg(0), flags.Arg(1), flags.Arg(2)
	switch strings.ToLower(typeArg) {
	case "cert":
		fallthrough
	case "certificate":
		if err := format.Cert(sourceFormat, targetFormat, inArg, outArg); err != nil {
			if errors.Is(err, format.ErrCancelOverwrite) {
				fmt.Println(err.Error())
				os.Exit(0)
			}
			fmt.Println(err.Error())
			os.Exit(1)
		}
	case "key":
		fallthrough
	case "private_key":
		if err := format.Key(sourceFormat, targetFormat, inArg, outArg); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown file type '%s'", typeArg)
		os.Exit(1)
	}
}
