package business

import (
	"bufio"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrUserCancelled = errors.New("user cancelled input")
)

func PromptCertNameDetails() (pkix.Name, error) {
	name := pkix.Name{}
	scanner := &nameFieldScanner{Scanner: bufio.NewScanner(os.Stdin)}
	continuePrompt := true

	for continuePrompt {
		scanned := false
		fmt.Println("\nEnter certificate name details.")
		scanner.ScanField("Country", &name.Country)
		scanner.ScanField("Organization", &name.Organization)
		scanner.ScanField("Organizational Unit", &name.OrganizationalUnit)
		scanner.ScanField("Street Address", &name.StreetAddress)
		scanner.ScanField("Locality", &name.Locality)
		scanner.ScanField("Province", &name.Locality)
		scanner.ScanField("Postal Code", &name.Locality)

		if scanner.scanCancelled {
			return name, ErrUserCancelled
		}

		fmt.Printf(`Are these details correct?
Country:             '%s'
Organization:        '%s'
Organizational Unit: '%s'
Street Address:      '%s'
Locality:            '%s'
Province:            '%s'
Postal Code:         '%s'

(y/n): `, valOrEmpty(name.Country), valOrEmpty(name.Organization), valOrEmpty(name.OrganizationalUnit),
			valOrEmpty(name.StreetAddress), valOrEmpty(name.Locality), valOrEmpty(name.Province), valOrEmpty(name.PostalCode))
		scanned = scanner.Scan()
		if !scanned {
			return name, ErrUserCancelled
		}
		if answer := scanner.Text(); strings.ToLower(answer) == "y" {
			continuePrompt = false
		}
	}

	return name, nil
}

func valOrEmpty(field []string) string {
	if len(field) == 0 {
		return ""
	}
	return field[0]
}

type nameFieldScanner struct {
	*bufio.Scanner
	scanCancelled bool
}

func (f *nameFieldScanner) ScanField(name string, field *[]string) {
	if f.scanCancelled {
		return
	}
	fmt.Printf("%s: ", name)
	f.scanCancelled = !f.Scanner.Scan()
	if !f.scanCancelled {
		*field = []string{f.Scanner.Text()}
	}
}
