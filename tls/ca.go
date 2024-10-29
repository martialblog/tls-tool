package tls

import (
	"crypto/x509/pkix"
	"errors"
	"os"
	"slices"
)

// CA is a certificate authority
type CA struct {
	Domain                string
	Constraint            bool
	AdditionalConstraints []string
	Subject               pkix.Name
	Days                  int
}

// Create creates the CA certificate and key
func (ca *CA) Create() (err error) {
	const certFileName = "ca.pem"

	const pkFileName = "ca-key.pem"

	if !(fileDoesNotExist(certFileName)) {
		return errors.New(certFileName + " already exists")
	}

	if !(fileDoesNotExist(pkFileName)) {
		return errors.New(pkFileName + " already exists")
	}

	serialNumber, err := GenerateSerialNumber()

	if err != nil {
		return err
	}

	signer, pk, err := GeneratePrivateKey()

	if err != nil {
		return err
	}

	constraints := make([]string, 0, len(ca.AdditionalConstraints)+1)

	if ca.Constraint {
		constraints = slices.Concat(ca.AdditionalConstraints, []string{ca.Domain, "localhost"})
	}

	if ca.Subject.CommonName == "" {
		ca.Subject.CommonName = ca.Domain + " " + serialNumber.String()
	}

	caCert, err := GenerateCA(signer, serialNumber, ca.Days, constraints, ca.Subject)

	if err != nil {
		return err
	}

	caFile, err := os.Create(certFileName)

	if err != nil {
		return err
	}

	//nolint:errcheck
	caFile.WriteString(caCert)

	pkFile, err := os.Create(pkFileName)

	if err != nil {
		return err
	}

	//nolint:errcheck
	pkFile.WriteString(pk)

	return nil
}
