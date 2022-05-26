package format

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type Encoding int

const (
	EncodingDer Encoding = iota
	EncodingPem
)

var (
	ErrCancelOverwrite = errors.New("user declined to overwrite")
)

func Cert(sourceFmt, targetFmt Encoding, inFile, outFile string) error {
	exists, err := fileExists(outFile)
	if err != nil {
		return err
	}
	if exists {
		if !confirmOverwrite(outFile) {
			return ErrCancelOverwrite
		}
	}
	inBytes, err := ioutil.ReadFile(inFile)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	switch sourceFmt {
	case EncodingPem:
		block, _ := pem.Decode(inBytes)
		inBytes = block.Bytes
	case EncodingDer:
		// No op, DER is the normalized form.
	}
	switch targetFmt {
	case EncodingPem:
		err := pem.Encode(out, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: inBytes,
		})
		if err != nil {
			return err
		}
	case EncodingDer:
		buf := bytes.NewBuffer(inBytes)
		if _, err := io.Copy(out, buf); err != nil {
			return err
		}
	}
	return nil
}

func Key(sourceFmt, targetFmt Encoding, inFile, outFile string) error {
	exists, err := fileExists(outFile)
	if err != nil {
		return err
	}
	if exists {
		if !confirmOverwrite(outFile) {
			return ErrCancelOverwrite
		}
	}
	inBytes, err := ioutil.ReadFile(inFile)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	switch sourceFmt {
	case EncodingPem:
		block, _ := pem.Decode(inBytes)
		inBytes = block.Bytes
	case EncodingDer:
		// No op, DER is the normalized form.
	}
	switch targetFmt {
	case EncodingPem:
		err := pem.Encode(out, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: inBytes,
		})
		if err != nil {
			return err
		}
	case EncodingDer:
		buf := bytes.NewBuffer(inBytes)
		if _, err := io.Copy(out, buf); err != nil {
			return err
		}
	}
	return nil
}

func confirmOverwrite(filename string) bool {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Are you sure you want to overwrite '%s'? (y/n) ", filename)
	if !scanner.Scan() {
		return false
	}
	answer := strings.ToLower(scanner.Text())
	if answer == "y" {
		return true
	}
	return false
}

func fileExists(filename string) (bool, error) {
	_, err := os.Stat(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
