package handlers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"ca/internal/db"
	"ca/internal/hsm"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type CertificateRepository struct {
	hsm *hsm.Hsm
	db  *mongo.Client
}

func BuildCertificateRepository(hsm *hsm.Hsm, db *mongo.Client) CertificateRepository {
	return CertificateRepository{
		hsm: hsm,
		db:  db,
	}
}

func (repo *CertificateRepository) CreateIdentityCommitment(email string, publicKeyDer []byte, keyType string) string {
	limit := new(big.Int).Lsh(big.NewInt(1), 2048)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return ""
	}

	commitment := db.IdentityCommitment{
		ID:                   primitive.NewObjectID(),
		Challenge:            GenerateChallenge(),
		Email:                email,
		PublicKeyDER:         publicKeyDer,
		KeyType:              keyType,
		ValidFrom:            primitive.NewDateTimeFromTime(time.Now()),
		ValidUntil:           primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24)), //  Commitments are valid for one day
		Proof:                nil,
		ReservedSerialNumber: *serialNumber,
	}

	//Store the certificate in the database
	err = db.StoreIdentityCommitment(repo.db, commitment)
	if err != nil {
		fmt.Println("Unable to store identity commitment: ", err)
	}

	return commitment.Challenge
}

func (repo *CertificateRepository) CreateCertificate(email string, clientPublicKey crypto.PublicKey, serial big.Int) ([]byte, error) {
	// Create client certificate template
	now := time.Now()
	oneYearFromNow := now.Add(time.Hour * 24 * 365)

	clientCertTemplate := &x509.Certificate{
		SerialNumber: &serial,
		Subject: pkix.Name{
			CommonName: email,
		},
		EmailAddresses:        []string{email},
		NotBefore:             now,
		NotAfter:              oneYearFromNow,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}

	// Load root certificate
	caCertPEM, err := os.ReadFile("/certs/root.pem")
	if err != nil {
		return nil, err
	}
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Create signer
	signer, err := repo.hsm.BuildECDSASigner(context.Background())
	if err != nil {
		return nil, err
	}

	// Create client certificate with CA certificate as parent
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		clientCertTemplate,
		caCert,
		clientPublicKey,
		signer,
	)
	if err != nil {
		return nil, err
	}

	// Encode certificate in PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	pemData := pem.EncodeToMemory(pemBlock)

	// Store certificate data
	certData := db.CertificateData{
		SerialNumber: serial,
		ValidFrom:    primitive.NewDateTimeFromTime(time.Now()),
		ValidUntil:   primitive.NewDateTimeFromTime(oneYearFromNow),
		Revoked:      false,
	}
	err = db.StoreCertificateData(repo.db, certData)
	if err != nil {
		return nil, err
	}

	return pemData, nil
}

func (repo *CertificateRepository) GetCommitmentFromChallenge(challenge string) *db.IdentityCommitment {
	commitment, err := db.RetrieveIdentityCommittment(repo.db, challenge)

	if err != nil {
		fmt.Println("[-] Unable to retrieve identity commitment: ", err)
		return nil
	}

	return commitment
}

func (repo *CertificateRepository) GetCommitmentFromReservedSerialNumber(serial big.Int) *db.IdentityCommitment {
	commitment, err := db.RetrieveIdentityCommittmentFromReservedSerial(repo.db, serial)

	if err != nil {
		fmt.Println("[-] Unable to retrieve identity commitment: ", err)
		return nil
	}

	return commitment
}

// func (repo *CertificateRepository) RevokeCertificateByID(serialNumber string) error {
// 	// Revoke the certificate by serial number
// 	panic("unimplemented")
// }

func (repo *CertificateRepository) VerifyChallenge(challenge, response, publicKey []byte) bool {
	// Use cryptographic methods to verify the response
	return repo.verifySignature(challenge, response, publicKey)
}

// func (repo *CertificateRepository) verifySignature(challenge, response, publicKey []byte) bool {
// 	panic("unimplemented")
// }

// RevokeCertificateByID revokes a certificate by its serial number
func (repo *CertificateRepository) RevokeCertificateByID(serialNumber *big.Int) error {
	// Update the certificate status in the database
	err := db.RevokeCertificate(repo.db, *serialNumber)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate with serial %s: %w", serialNumber, err)
	}

	log.Printf("[+] Certificate with serial number %s has been revoked", serialNumber)
	return nil
}

// verifySignature verifies a cryptographic signature against a challenge using the provided public key
func (repo *CertificateRepository) verifySignature(challenge, response, publicKeyDER []byte) bool {
	// Parse the public key from DER format
	publicKey := repo.ValidatePublicKey(publicKeyDER)
	if publicKey == nil {
		log.Printf("[-] Invalid public key provided for signature verification")
		return false
	}

	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		return repo.verifyECDSASignature(challenge, response, key)
	case *rsa.PublicKey:
		return repo.verifyRSASignature(challenge, response, key)
	default:
		log.Printf("[-] Unsupported key type for signature verification: %T", key)
		return false
	}
}

func (repo *CertificateRepository) verifyECDSASignature(challenge, signature []byte, publicKey *ecdsa.PublicKey) bool {
	// Hash the challenge using SHA-256
	hash := crypto.SHA256.New()
	hash.Write(challenge)
	hashed := hash.Sum(nil)

	// Decode the signature from base64
	sigBytes, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		log.Printf("[-] Failed to decode ECDSA signature: %v", err)
		return false
	}

	// Parse the signature (assuming ASN.1 DER format)
	// For ECDSA, we need to extract r and s values
	if len(sigBytes) < 8 { // Minimum reasonable size for ECDSA signature
		log.Printf("[-] ECDSA signature too short")
		return false
	}

	// Simple parsing assuming r and s are equal length and concatenated
	// In production, you'd want proper ASN.1 DER parsing
	sigLen := len(sigBytes)
	if sigLen%2 != 0 {
		log.Printf("[-] Invalid ECDSA signature length")
		return false
	}

	rBytes := sigBytes[:sigLen/2]
	sBytes := sigBytes[sigLen/2:]

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	// Verify the signature
	valid := ecdsa.Verify(publicKey, hashed, r, s)
	if !valid {
		log.Printf("[-] ECDSA signature verification failed")
	}

	return valid
}

func (repo *CertificateRepository) verifyRSASignature(challenge, signature []byte, publicKey *rsa.PublicKey) bool {
	// Hash the challenge using SHA-256
	hash := crypto.SHA256.New()
	hash.Write(challenge)
	hashed := hash.Sum(nil)

	// Decode the signature from base64
	sigBytes, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		log.Printf("[-] Failed to decode RSA signature: %v", err)
		return false
	}

	// Verify the signature using PSS padding (recommended for new applications)
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, sigBytes, nil)
	if err != nil {
		// Try PKCS#1 v1.5 as fallback
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, sigBytes)
		if err != nil {
			log.Printf("[-] RSA signature verification failed: %v", err)
			return false
		}
	}

	return true
}

func (repo *CertificateRepository) ValidatePublicKey(publicKey []byte) crypto.PublicKey {
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(publicKey)
		if err != nil {
			log.Printf("[-] Error while parsing public key: %v", err)
			return nil
		}
	}

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return key
	case *rsa.PublicKey:
		if key.Size() < 256 {
			log.Printf("[-] RSA public key is too small: %d bits", key.Size()*8)
			return nil
		}
		return key
	}

	log.Printf("[-] Unsupported public key type: %T", pub)
	return nil
}

func GenerateChallenge() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}
