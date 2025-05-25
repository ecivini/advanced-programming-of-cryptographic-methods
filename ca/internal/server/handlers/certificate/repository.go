package handlers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
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
	err := db.StoreIdentityCommitment(repo.db, commitment)
	if err != nil {
		fmt.Println("Unable to store identity commitment: ", err)
	}

	return commitment.Challenge
}

func (repo *CertificateRepository) CreateCertificate(email string, clientPublicKey crypto.PublicKey) ([]byte, error) {
	// Create client certificate template
	now := time.Now()
	oneYearFromNow := now.Add(time.Hour * 24 * 365)

	// Create random serial number
	limit := new(big.Int).Lsh(big.NewInt(1), 2048)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.New("unable to generate serial number")
	}

	clientCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
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

func (repo *CertificateRepository) GetCommitmentFromChallenge(challenge string) *db.IdentityCommitment {
	commitment, err := db.RetrieveIdentityCommittment(repo.db, challenge)

	if err != nil {
		fmt.Println("[-] Unable to retrieve identity commitment: ", err)
		return nil
	}

	return commitment
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
