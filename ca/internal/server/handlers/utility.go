package handlers

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"ca/internal/db"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var ErrInvalidEmail = errors.New("invalid email")

func GenerateCertificate(email string, publicKey []byte) (*db.IssuedCertificate, error) {

	// Validate the email
	if !ValidateEmail(email) {
		return nil, ErrInvalidEmail
	}

	// Validate the public key
	if err := ValidatePublicKey(publicKey); err != nil {
		return nil, err
	}

	// Generate a new certificate
	certificate := &db.IssuedCertificate{
		ID:           primitive.NewObjectID(),
		Challenge:    GenerateChallenge(),
		Email:        email,
		PublicKey:    publicKey,
		ChallengedAt: primitive.NewDateTimeFromTime(time.Now()),
		ValidFrom:    primitive.NewDateTimeFromTime(time.Now()),
		ValidUntil:   primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24 * 365)),
	}

	//TODO: Load private key from HSM
	// Sign the certificate
	//certificate.Sign(rand.Reader, certificate, publicKey, nil, nil) //nil is the private key

	//Store the certificate in the database
	db.SaveIssuedCertificate(*certificate)

	return certificate, nil

}

func RevokeCertificateByID(serialNumber string) error {
	// Revoke the certificate by serial number
	panic("unimplemented")
}

func VerifyChallenge(challenge, response, publicKey []byte) bool {
	// Use cryptographic methods to verify the response
	return verifySignature(challenge, response, publicKey)
}

func verifySignature(challenge, response, publicKey []byte) bool {
	panic("unimplemented")
}

func ValidateEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func ValidatePublicKey(publicKey []byte) error {
	// Check if the public key has a valid format
	_, err := x509.ParsePKIXPublicKey(publicKey)
	return err
}

func GenerateChallenge() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func ParseJSONBody(r *http.Request, target interface{}) error {
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(target)
	return err
}
