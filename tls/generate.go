package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// fileDoesNotExist tests if a given file exists
func fileDoesNotExist(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return true
	}

	return false
}

// GenerateSerialNumber returns random bigint generated with crypto/rand
func GenerateSerialNumber() (*big.Int, error) {
	l := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, l)

	if err != nil {
		return nil, err
	}

	return s, nil
}

// GeneratePrivateKey generates a new ecdsa private key
func GeneratePrivateKey() (crypto.Signer, string, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, "", fmt.Errorf("error generating private key: %w", err)
	}

	bs, err := x509.MarshalECPrivateKey(pk)

	if err != nil {
		return nil, "", fmt.Errorf("error generating private key: %w", err)
	}

	var buf bytes.Buffer

	err = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bs})

	if err != nil {
		return nil, "", fmt.Errorf("error encoding private key: %w", err)
	}

	return pk, buf.String(), nil
}

// GenerateCA generates a new CA for agent TLS (not to be confused with Connect TLS)
func GenerateCA(signer crypto.Signer, sn *big.Int, days int, constraints []string, subject pkix.Name) (string, error) {
	id, err := keyID(signer.Public())
	if err != nil {
		return "", err
	}

	// Create the CA cert
	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               subject,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		NotAfter:              time.Now().AddDate(0, 0, days),
		NotBefore:             time.Now(),
		AuthorityKeyId:        id,
		SubjectKeyId:          id,
	}

	if len(constraints) > 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = constraints
	}

	bs, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), signer)

	if err != nil {
		return "", fmt.Errorf("error generating CA certificate: %w", err)
	}

	var buf bytes.Buffer

	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})

	if err != nil {
		return "", fmt.Errorf("error encoding private key: %w", err)
	}

	return buf.String(), nil
}

// GenerateCert generates a new certificate for agent TLS (not to be confused with Connect TLS)
func GenerateCert(signer crypto.Signer, ca string, sn *big.Int, name string, days int, dnsnames []string, ipaddresses []net.IP, extKeyUsage []x509.ExtKeyUsage) (string, string, error) {
	parent, err := parseCert(ca)
	if err != nil {
		return "", "", err
	}

	signee, pk, err := GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}

	id, err := keyID(signee.Public())
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage,
		IsCA:                  false,
		NotAfter:              time.Now().AddDate(0, 0, days),
		NotBefore:             time.Now(),
		SubjectKeyId:          id,
		DNSNames:              dnsnames,
		IPAddresses:           ipaddresses,
	}

	bs, err := x509.CreateCertificate(rand.Reader, &template, parent, signee.Public(), signer)

	if err != nil {
		return "", "", err
	}

	var buf bytes.Buffer

	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})

	if err != nil {
		return "", "", fmt.Errorf("error encoding private key: %w", err)
	}

	return buf.String(), pk, nil
}

// keyId returns a x509 KeyId from the given signing key.
func keyID(raw interface{}) ([]byte, error) {
	switch raw.(type) {
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("invalid key type: %T", raw)
	}

	// This is not standard; RFC allows any unique identifier as long as they
	// match in subject/authority chains but suggests specific hashing of DER
	// bytes of public key including DER tags.
	bs, err := x509.MarshalPKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	// String formatted
	kID := sha256.Sum256(bs)

	return []byte(strings.ReplaceAll(fmt.Sprintf("% x", kID), " ", ":")), nil
}

func parseCert(pemValue string) (*x509.Certificate, error) {
	// The _ result below is not an error but the remaining PEM bytes.
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("no PEM-encoded data found")
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("first PEM-block should be CERTIFICATE type")
	}

	return x509.ParseCertificate(block.Bytes)
}

// ParseSigner parses a crypto.Signer from a PEM-encoded key. The private key
// is expected to be the first block in the PEM value.
func ParseSigner(pemValue string) (crypto.Signer, error) {
	// The _ result below is not an error but the remaining PEM bytes.
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("no PEM-encoded data found")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unknown PEM block type for signing key: %s", block.Type)
	}
}

// Verify certificate
func Verify(caString, certString, dns string) error {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(caString))

	if !ok {
		return errors.New("failed to parse root certificate")
	}

	cert, err := parseCert(certString)

	if err != nil {
		return errors.New("failed to parse certificate")
	}

	opts := x509.VerifyOptions{
		DNSName: dns,
		Roots:   roots,
	}

	_, err = cert.Verify(opts)

	return err
}
