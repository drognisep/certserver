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
		sourceFormat string
		targetFormat string
	)

	flags.StringVar(&sourceFormat, "source", "", "Specifies what format the IN_FILE is in")
	flags.StringVar(&targetFormat, "target", "", "Specify what format the OUT_FILE should be")
	if err := flags.Parse(args); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if sourceFormat == "" {
		fmt.Println("Must specify a source format")
		flags.Usage()
		os.Exit(1)
	}
	if targetFormat == "" {
		fmt.Println("Must specify a target format")
		flags.Usage()
		os.Exit(1)
	}

	targetEncoding := mapEncoding(targetFormat)
	sourceEncoding := mapEncoding(sourceFormat)
	if sourceEncoding == targetEncoding {
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
		if err := format.Cert(sourceEncoding, targetEncoding, inArg, outArg); err != nil {
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
		if err := format.Key(sourceEncoding, targetEncoding, inArg, outArg); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown file type '%s'", typeArg)
		os.Exit(1)
	}
}

func mapEncoding(targetFormat string) format.Encoding {
	var targetEncoding format.Encoding
	switch strings.ToLower(targetFormat) {
	case "der":
		targetEncoding = format.EncodingDer
	case "pem":
		targetEncoding = format.EncodingPem
	default:
		fmt.Printf("Unknown target format '%s'\n", targetFormat)
		os.Exit(1)
	}
	return targetEncoding
}
