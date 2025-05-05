package db

import (
	"io"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type IdentityCommitment struct {
	ID           primitive.ObjectID `bson:"_id,nonempty,unique"`
	Challenge    string             `bson:"challenge,nonempty"`
	Email        string             `bson:"email,nonempty"`
	PublicKeyDER []byte             `bson:"public_key_der,nonempty"`
	KeyType      string             `bson:"key_type,nonempty"`
	ValidFrom    primitive.DateTime `bson:"valid_from,nonempty"`
	ValidUntil   primitive.DateTime `bson:"valid_until,nonempty"`
	Proof        []byte             `bson:"signature,omitempty"`
}

type RevocatedCertificate struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	CertificateId  string             `bson:"certificate_id,omitempty"`
	RevocationDate string             `bson:"revocation_date,omitempty"`
}

type IssuedCertificate struct {
	ID                primitive.ObjectID `bson:"_id,omitempty"`
	Challenge         string             `bson:"challenge,omitempty"`
	Email             string             `bson:"email,omitempty"`
	PublicKey         []byte             `bson:"public_key,omitempty"`
	ChallengedAt      primitive.DateTime `bson:"challenged_at,omitempty"`
	VerifiedAt        primitive.DateTime `bson:"verified_at,omitempty"`
	VerifiedSignature []byte             `bson:"signature,omitempty"`
	ValidFrom         primitive.DateTime `bson:"valid_from,omitempty"`
	ValidUntil        primitive.DateTime `bson:"valid_until,omitempty"`
	RawCertificate    []byte             `bson:"raw_certificate,omitempty"`
}

func (i *IssuedCertificate) Sign(rand io.Reader, template *IssuedCertificate, parent *IssuedCertificate, pub interface{}, priv interface{}) ([]byte, error) {
	// Add logic to sign the certificate
	panic("unimplemented")
}

func GenerateChallenge() string {
	panic("unimplemented")
}
