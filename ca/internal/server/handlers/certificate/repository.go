package handlers

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
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
	commitment := db.IdentityCommitment{
		ID:           primitive.NewObjectID(),
		Challenge:    GenerateChallenge(),
		Email:        email,
		PublicKeyDER: publicKeyDer,
		KeyType:      keyType,
		ValidFrom:    primitive.NewDateTimeFromTime(time.Now()),
		ValidUntil:   primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24)), //  Commitments are valid for one day
		Proof:        nil,
	}

	//Store the certificate in the database
	db.StoreIdentityCommitment(repo.db, commitment)

	return commitment.Challenge
}

func (repo *CertificateRepository) CreateCertificate(email string, clientPublicKeyPEM []byte) ([]byte, error) {
	// Validate client public key
	clientPublicKeyPEMBlock, _ := pem.Decode(clientPublicKeyPEM)
	clientPublicKey, err := x509.ParsePKIXPublicKey(clientPublicKeyPEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Create client certificate template
	now := time.Now()
	oneYearFromNow := now.Add(time.Hour * 24 * 365)

	clientCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
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

	return pemData, nil

}

func (repo *CertificateRepository) RevokeCertificateByID(serialNumber string) error {
	// Revoke the certificate by serial number
	panic("unimplemented")
}

func (repo *CertificateRepository) VerifyChallenge(challenge, response, publicKey []byte) bool {
	// Use cryptographic methods to verify the response
	return repo.verifySignature(challenge, response, publicKey)
}

func (repo *CertificateRepository) verifySignature(challenge, response, publicKey []byte) bool {
	panic("unimplemented")
}

func (repo *CertificateRepository) ValidatePublicKey(publicKey []byte) error {
	// Check if the public key has a valid format
	_, err := x509.ParsePKIXPublicKey(publicKey)
	return err
}

func GenerateChallenge() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}
