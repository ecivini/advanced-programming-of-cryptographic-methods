package handlers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"ca/internal/db"
	"ca/internal/hsm"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type ECDSASignature struct {
	R, S *big.Int
}

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
	limit := new(big.Int).Lsh(big.NewInt(1), 256)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return ""
	}

	commitment := db.IdentityCommitment{
		ID:                   bson.NewObjectID(),
		Challenge:            GenerateChallenge(),
		Email:                email,
		PublicKeyDER:         publicKeyDer,
		KeyType:              keyType,
		ValidFrom:            bson.NewDateTimeFromTime(time.Now()),
		ValidUntil:           bson.NewDateTimeFromTime(time.Now().Add(time.Hour * 24)), //  Commitments are valid for one day
		Proof:                nil,
		ReservedSerialNumber: serialNumber.String(),
	}

	//Store the certificate in the database
	err = db.StoreIdentityCommitment(repo.db, commitment)
	if err != nil {
		fmt.Println("Unable to store identity commitment: ", err)
	}

	return commitment.Challenge
}

func (repo *CertificateRepository) CreateCertificate(email string, clientPublicKey crypto.PublicKey, serial *big.Int) ([]byte, error) {
	// Create client certificate template
	now := time.Now()
	oneYearFromNow := now.Add(time.Hour * 24 * 365)

	clientCertTemplate := &x509.Certificate{
		SerialNumber: serial,
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
		SerialNumber: serial.String(),
		ValidFrom:    bson.NewDateTimeFromTime(now),
		ValidUntil:   bson.NewDateTimeFromTime(oneYearFromNow),
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

func (repo *CertificateRepository) GetCommitmentFromReservedSerialNumber(serial string) *db.IdentityCommitment {
	commitment, err := db.RetrieveIdentityCommittmentFromReservedSerial(repo.db, serial)

	if err != nil {
		fmt.Println("[-] Unable to retrieve identity commitment: ", err)
		return nil
	}

	return commitment
}

func (repo *CertificateRepository) GetStatusFromSerialNumber(serial string) *db.CertificateData {
	certificateData, err := db.RetrieveCertificateData(repo.db, serial)
	if err != nil {
		fmt.Println("[-] Unable to retrieve certificate data: ", err)
		return nil
	}
	return certificateData
}

func (repo *CertificateRepository) GetRevokedCertificates(page, pageSize int) ([]db.CertificateData, error) {
	// Retrieve revoked certificates from the database with pagination
	certificates, err := db.GetRevokedCertificates(repo.db, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve revoked certificates: %w", err)
	}

	log.Printf("[+] Retrieved %d revoked certificates", len(certificates))
	return certificates, nil
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
func (repo *CertificateRepository) RevokeCertificateByID(serialNumber string) error {
	// Update the certificate status in the database
	err := db.RevokeCertificate(repo.db, serialNumber)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate with serial %s: %w", serialNumber, err)
	}

	log.Printf("[+] Certificate with serial number %s has been revoked", serialNumber)
	return nil
}

// verifySignature verifies a cryptographic signature against a challenge using the provided public key
func (repo *CertificateRepository) verifySignature(message, response, publicKeyDER []byte) bool {
	// Parse the public key from DER format
	publicKey := repo.ValidatePublicKey(publicKeyDER)
	if publicKey == nil {
		log.Printf("[-] Invalid public key provided for signature verification")
		return false
	}

	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		return repo.verifyECDSASignature(message, response, key)
	case *rsa.PublicKey:
		return repo.verifyRSASignature(message, response, key)
	default:
		log.Printf("[-] Unsupported key type for signature verification: %T", key)
		return false
	}
}

func (repo *CertificateRepository) verifyECDSASignature(message, rawSignature []byte, publicKey *ecdsa.PublicKey) bool {
	var signature ECDSASignature
	_, err := asn1.Unmarshal(rawSignature, &signature)
	if err != nil {
		log.Printf("[-] Failed to decode ECDSA signature: %v", err)
		return false
	}

	hashedMessage := sha256.Sum256(message)
	return ecdsa.Verify(publicKey, hashedMessage[:], signature.R, signature.S)
}

func (repo *CertificateRepository) verifyRSASignature(message, signatureBytes []byte, publicKey *rsa.PublicKey) bool {
	hashedMessage := sha256.Sum256(message)

	// Verify the signature using PSS padding (recommended for new applications)
	err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashedMessage[:], signatureBytes, nil)
	if err != nil {
		// Try PKCS#1 v1.5 as fallback
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedMessage[:], signatureBytes)
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
