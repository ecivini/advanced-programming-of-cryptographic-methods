package db

import "go.mongodb.org/mongo-driver/bson/primitive"

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
}
