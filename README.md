# tls-tool

Fork of https://github.com/ribbybibby/tls-tool

## Usage

```bash
tls-tool -help
usage: tls-tool [<flags>] <command> [<args> ...]

A tool for creating TLS certificates quickly

Flags:
  -help  Show context-sensitive help

Commands:
  ca [<flags>]
    Create a new certificate authority

  cert [<flags>]
    Create a new certificate
```

Usage of the CA subcommand:

```bash
tls-tool ca -help
usage: tls-tool ca [<flags>]

Create a new certificate authority

Flags:
-additional-name-constraint value
      Add additional name constraints for the CA
-country string
      Country code for the new CA (default "GB")
-days int
      Number of days the CA is valid (default 1825)
-domain string
      Domain name for the new CA (default "ribbybibby.me")
-locality string
      Locality for the new CA (default "London")
-name-constraint
      Add name constraints for the CA
-organization string
      Organization for the new CA (default "ribbybibby")
-postal-code string
      Postal code for the new CA (default "SW18XXX")
-province string
      Province for the new CA (default "England")
-street-address string
      Street Address for the new CA (default "123 Fake St")
```

Usage of the certificate subcommand:

```bash
tls-tool cert -help

usage: tls-tool cert [<flags>]

Create a new certificate

Flags:
-additional-dnsname value
      Provide additional dnsnames for Subject Alternative Names
-ca string
      Path to the CA certificate file (default "ca.pem")
-days int
      Number of days the certificate is valid for from now on (default 365)
-domain string
      Domain for the new certificate (default "ribbybibby.me")
-insecure
      Optionally allow the creation of purposely expired or otherwise invalid certs
-ipaddresses value
      Provide IPs for Subject Alternative Names
-key string
      Path to the CA key file (default "ca-key.pem")
```

## Examples

Create a CA:

```bash
tls-tool ca

ca.pem
ca-key.pem
```

Create a certificate:

```bash
tls-tool cert

cert-ribbybibby.me-0.pem
cert-ribbybibby.me-0-key.pem
```

```bash
tls-tool cert -additional-dnsname foobar.internal -additional-dnsname example.internal

cert-ribbybibby.me-1.pem
cert-ribbybibby.me-1-key.pem
```

Verification:

```bash
openssl x509 -inform pem -noout -text -in cert-ribbybibby.me-0.pem
```
