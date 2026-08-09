package tlscert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSignedCert handles the -gen-cert flow
func GenerateSelfSignedCert(host, org string) {
	certDir := "tls_certs"
	certFile := filepath.Join(certDir, "tls_server.crt")
	keyFile := filepath.Join(certDir, "tls_server.key")

	// Ensure directory exists
	if err := os.MkdirAll(certDir, 0750); err != nil {
		fmt.Printf("Error creating directory %s: %v\n", certDir, err)
		os.Exit(1)
	}

	// Check if files exist and are valid
	if fileExists(certFile) && fileExists(keyFile) {
		// Validate expiry
		valid := false
		if certBytes, err := os.ReadFile(certFile); err == nil {
			block, _ := pem.Decode(certBytes)
			if block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if time.Now().Before(cert.NotAfter) {
						valid = true
					}
				}
			}
		}

		if valid {
			fmt.Printf("Valid certificates found at %s/, skipping generation.\n", certDir)
			return
		}
		fmt.Println("Existing certificates are invalid or expired. Regenerating...")
	}

	fmt.Printf("Generating self-signed certificate for host '%s'...\n", host)
	fmt.Println("WARNING: This certificate is for TESTING ONLY. Browsers will warn about it.")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	// Random 128-bit serial — mirrors crypto/tls/generate_cert.go's pattern.
	// A fixed serial of 1 would make distinct self-signed certs collide in a
	// trust store and confuses some browsers when rotating between test CAs.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		fmt.Printf("Failed to generate certificate serial: %v\n", err)
		os.Exit(1)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: now,
		NotAfter:  now.Add(365 * 24 * time.Hour), // 1 Year
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}
	// Always add localhost for convenience
	template.DNSNames = append(template.DNSNames, "localhost")
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Printf("Failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	// Write files — cert is public (0644), key is owner-only (0600).
	writePublicPEM(certFile, "CERTIFICATE", derBytes)
	writePrivatePEM(keyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))

	fmt.Printf("Successfully generated:\n - %s\n - %s\n", certFile, keyFile)
	fmt.Println("\nUsage:")
	fmt.Printf("export IDENTUUM_IDP_TLS_CERT_FILE=$(pwd)/%s\n", certFile)
	fmt.Printf("export IDENTUUM_IDP_TLS_KEY_FILE=$(pwd)/%s\n", keyFile)
}

// GenerateCSR handles the -gen-csr flow
func GenerateCSR(host, org string) {
	certDir := "tls_certs"
	csrFile := filepath.Join(certDir, "tls_server.csr")
	keyFile := filepath.Join(certDir, "tls_server.key")

	// Ensure directory exists
	if err := os.MkdirAll(certDir, 0750); err != nil {
		fmt.Printf("Error creating directory %s: %v\n", certDir, err)
		os.Exit(1)
	}

	var priv *rsa.PrivateKey
	var err error

	// 1. Generate or Load Private Key
	if fileExists(keyFile) {
		fmt.Printf("Found existing key at %s. Reusing it.\n", keyFile)
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Printf("Error reading key file: %v\n", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			fmt.Println("Failed to decode existing key. Please delete it to regenerate.")
			os.Exit(1)
		}
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			fmt.Printf("Error parsing private key: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Generating new 2048-bit RSA private key...")
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("Failed to generate private key: %v\n", err)
			os.Exit(1)
		}
		writePrivatePEM(keyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	}

	// 2. Generate CSR
	subj := pkix.Name{
		CommonName:   host,
		Organization: []string{org},
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	if ip := net.ParseIP(host); ip != nil {
		csrTemplate.IPAddresses = append(csrTemplate.IPAddresses, ip)
	} else {
		csrTemplate.DNSNames = append(csrTemplate.DNSNames, host)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv)
	if err != nil {
		fmt.Printf("Failed to create CSR: %v\n", err)
		os.Exit(1)
	}

	writePublicPEM(csrFile, "CERTIFICATE REQUEST", csrBytes)

	fmt.Printf("Successfully generated CSR:\n - %s\n", csrFile)
	if !fileExists(keyFile) { // If we just generated it
		fmt.Printf(" - %s\n", keyFile)
	}
	fmt.Println("\nNext Steps:")
	fmt.Println("1. Send tls_server.csr to your Certificate Authority (IT/Security Team).")
	fmt.Println("2. Save the signed certificate as tls_server.crt in this directory.")
	fmt.Println("3. Configure the server:")
	fmt.Printf("   export IDENTUUM_IDP_TLS_CERT_FILE=$(pwd)/%s/tls_server.crt\n", certDir)
	fmt.Printf("   export IDENTUUM_IDP_TLS_KEY_FILE=$(pwd)/%s\n", keyFile)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writePublicPEM writes a PEM block to disk with default (world-readable)
// permissions. Intended for certificates and CSRs — public material that
// benefits from normal file-sharing semantics.
func writePublicPEM(path, typeStr string, bytes []byte) {
	out, err := os.Create(path)
	if err != nil {
		fmt.Printf("Error creating file %s: %v\n", path, err)
		os.Exit(1)
	}
	defer out.Close()
	if err := pem.Encode(out, &pem.Block{Type: typeStr, Bytes: bytes}); err != nil {
		fmt.Printf("Error writing PEM to %s: %v\n", path, err)
		os.Exit(1)
	}
}

// writePrivatePEM writes a PEM block to disk with owner-only (0600)
// permissions. Used for RSA private keys so that a compromised non-owner
// account on the same host — or a process in the same group on a filesystem
// that honours group perms — cannot read the material.
//
// Uses O_CREATE|O_TRUNC|O_WRONLY with mode 0600 and follows with an explicit
// os.Chmod to handle filesystems where umask narrows file creation modes
// differently than the caller expects.
func writePrivatePEM(path, typeStr string, bytes []byte) {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Error creating file %s: %v\n", path, err)
		os.Exit(1)
	}
	defer out.Close()
	// Defensive: some umask / filesystem combinations can silently widen the
	// effective mode. Re-chmod to 0600 to make the invariant explicit.
	if err := os.Chmod(path, 0600); err != nil {
		fmt.Printf("Error chmodding file %s to 0600: %v\n", path, err)
		os.Exit(1)
	}
	if err := pem.Encode(out, &pem.Block{Type: typeStr, Bytes: bytes}); err != nil {
		fmt.Printf("Error writing PEM to %s: %v\n", path, err)
		os.Exit(1)
	}
}
