package tls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
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
	ExtKeyUsage []x509.ExtKeyUsage
}

// Create the certificate
func (c *Cert) Create() (err error) {
	var (
		signer       crypto.Signer
		serialNumber *big.Int
		dnsnames     []string
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

	var pkFileName, certFileName string

	// Check now many cert and key pairs have been created already
	createdCerts, _ := filepath.Glob("*-key.pem")

	for i := range createdCerts {
		tmpCert := fmt.Sprintf("%s-%d-cert.pem", c.Domain, i)
		tmpPk := fmt.Sprintf("%s-%d-key.pem", c.Domain, i)

		if fileDoesNotExist(tmpCert) && fileDoesNotExist(tmpPk) {
			certFileName = tmpCert
			pkFileName = tmpPk

			break
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

	public, private, err := GenerateCert(
		signer,
		string(caCert),
		serialNumber,
		c.Domain,
		c.Days,
		dnsnames,
		c.IPAddresses,
		c.ExtKeyUsage)

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
