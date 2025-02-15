package tls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
)

// Cert is a certificate
type Cert struct {
	CAFile      string
	Domain      string
	Days        int
	KeyFile     string
	DNSNames    []string
	IPAddresses []net.IP
	Insecure    bool
}

// Create the certificate
func (c *Cert) Create() (err error) {
	var (
		signer       crypto.Signer
		serialNumber *big.Int
		dnsnames     []string
		extKeyUsage  []x509.ExtKeyUsage
		prefix       string
	)

	if c.CAFile == "" {
		return errors.New("please provide the ca")
	}

	if c.KeyFile == "" {
		return errors.New("please provide the key")
	}

	for _, d := range c.DNSNames {
		if len(d) > 0 {
			dnsnames = append(dnsnames, strings.TrimSpace(d))
		}
	}

	dnsnames = append(dnsnames, []string{c.Domain, "localhost"}...)

	// TODO make these a CLI flag
	extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	prefix = "cert-" + c.Domain

	var pkFileName, certFileName string

	// TODO might be a cleaner way of doing this
	for i := range 100 {
		tmpCert := fmt.Sprintf("%s-%d.pem", prefix, i)
		tmpPk := fmt.Sprintf("%s-%d-key.pem", prefix, i)

		if fileDoesNotExist(tmpCert) && fileDoesNotExist(tmpPk) {
			certFileName = tmpCert
			pkFileName = tmpPk

			break
		}

		if i == 100 {
			return errors.New("could not find a filename that doesn't already exist")
		}
	}

	var caCert, caKey []byte
	caCert, err = os.ReadFile(c.CAFile)

	if err != nil {
		return fmt.Errorf("error reading CA: %w", err)
	}

	caKey, err = os.ReadFile(c.KeyFile)

	if err != nil {
		return fmt.Errorf("error reading CA key: %w", err)
	}

	signer, err = ParseSigner(string(caKey))

	if err != nil {
		return err
	}

	serialNumber, err = GenerateSerialNumber()

	if err != nil {
		return err
	}

	public, private, err := GenerateCert(signer, string(caCert), serialNumber, c.Domain, c.Days, dnsnames, c.IPAddresses, extKeyUsage)

	if err != nil {
		return err
	}

	if err = Verify(string(caCert), public, c.Domain); err != nil && !c.Insecure {
		return err
	}

	certFile, err := os.Create(certFileName)

	if err != nil {
		return err
	}

	//nolint:errcheck
	certFile.WriteString(public)

	pkFile, err := os.Create(pkFileName)

	if err != nil {
		return err
	}

	//nolint:errcheck
	pkFile.WriteString(private)

	return nil
}
