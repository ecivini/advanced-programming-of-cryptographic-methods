package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

// GenerateSelfSignedCertificate generates a self-signed certificate and private key for the CA
func GenerateSelfSignedCertificate() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	//Create a certificate template, KeyUsage and ExtKeyUsage are required for a CA certificate and BasicConstraintsValid and IsCA must be set to true (anche se a noi non servono teoricamente)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"CA"},
			CommonName:   "CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	//Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("failed to marshal EC private key: %v", err)
	}

	// Convert to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}

// HandleIssueCertificate generates a self-signed certificate and private key for the CA and displays the certificate in the browser
func HandleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	certPem, _, err := GenerateSelfSignedCertificate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain") //If you want to download the certificate as a file, change the content type to "application/x-pem-file"
	w.Write(certPem)
}

// (Per Ale) Ricorda di usare http e non https
func main() {
	http.HandleFunc("/issue-cert", HandleIssueCertificate)

	fmt.Println("CA Server on port 3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}
