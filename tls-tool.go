package main

import (
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ribbybibby/tls-tool/tls/ca"
	"github.com/ribbybibby/tls-tool/tls/cert"
)

func printUsage() {
	fmt.Fprintln(os.Stderr, `A tool for creating TLS certificates quickly

Usage:
	tls-tool [command]

Available Commands:
	ca     Create a new certificate authority
	cert   Create a new key and certificate`)
	os.Exit(1)
}

type stringSliceFlag []string

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

func main() {
	flag.Usage = printUsage

	caCmd := flag.NewFlagSet("ca", flag.ExitOnError)

	var caCreateAdditionalNameConstraints stringSliceFlag
	caCmd.Var(&caCreateAdditionalNameConstraints, "additional-name-constraint", "Add additional name constraints for the CA")

	caCreateDomain := caCmd.String("domain", "ribbybibby.me", "Domain name for the new CA")
	caCreateDays := caCmd.Int("days", 1825, "Number of days the CA is valid")
	caCreateNameConstraint := caCmd.Bool("name-constraint", false, "Add name constraints for the CA")
	caCreateCountry := caCmd.String("country", "GB", "Country code for the new CA")
	caCreatePostalCode := caCmd.String("postal-code", "SW18XXX", "Postal code for the new CA")
	caCreateProvince := caCmd.String("province", "England", "Province for the new CA")
	caCreateLocality := caCmd.String("locality", "London", "Locality for the new CA")
	caCreateStreetAddress := caCmd.String("street-address", "123 Fake St", "Street Address for the new CA")
	caCreateOrganization := caCmd.String("organization", "ribbybibby", "Organization for the new CA")

	certCmd := flag.NewFlagSet("cert", flag.ExitOnError)

	var certCreateAdditionalDNSnames stringSliceFlag
	certCmd.Var(&certCreateAdditionalDNSnames, "additional-dnsname", "Provide additional dnsnames for Subject Alternative Names")

	certCreateCAFile := certCmd.String("ca", "ca.pem", "Path to the CA certificate file")
	certCreateKeyFile := certCmd.String("key", "ca-key.pem", "Path to the CA key file")
	certCreateDays := certCmd.Int("days", 365, "Number of days the certificate is valid for from now on")
	certCreateDomain := certCmd.String("domain", "ribbybibby.me", "Domain for the new certificate")
	certCreateInsecure := certCmd.Bool("insecure", false, "Optionally allow the creation of purposely expired or otherwise invalid certs")

	if len(os.Args) < 2 {
		printUsage()
	}

	switch os.Args[1] {
	case "ca":
		caCmd.Parse(os.Args[2:])

		c := &ca.CA{
			AdditionalConstraints: caCreateAdditionalNameConstraints,
			Constraint:            *caCreateNameConstraint,
			Days:                  *caCreateDays,
			Domain:                *caCreateDomain,
			Subject: pkix.Name{
				Country:       []string{*caCreateCountry},
				PostalCode:    []string{*caCreatePostalCode},
				Province:      []string{*caCreateProvince},
				Locality:      []string{*caCreateLocality},
				StreetAddress: []string{*caCreateStreetAddress},
				Organization:  []string{*caCreateOrganization},
			},
		}
		err := c.Create()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	case "cert":
		certCmd.Parse(os.Args[2:])

		c := &cert.Cert{
			CAFile:   *certCreateCAFile,
			Days:     *certCreateDays,
			DNSNames: certCreateAdditionalDNSnames,
			Domain:   *certCreateDomain,
			Insecure: *certCreateInsecure,
			KeyFile:  *certCreateKeyFile,
		}
		err := c.Create()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	default:
		printUsage()
	}
}
