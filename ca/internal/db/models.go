package db

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

type IdentityCommitment struct {
	ID                   bson.ObjectID `bson:"_id,unique"`
	Challenge            string        `bson:"challenge,nonempty"`
	Email                string        `bson:"email,nonempty"`
	PublicKeyDER         []byte        `bson:"public_key_der,nonempty"`
	ValidFrom            bson.DateTime `bson:"valid_from,nonempty"`
	ValidUntil           bson.DateTime `bson:"valid_until,nonempty"`
	Proof                []byte        `bson:"proof,omitempty"`
	ReservedSerialNumber string        `bson:"reserved_serial_number,unique,nonempty"`
}

type CertificateData struct {
	ID             bson.ObjectID `bson:"_id,unique"`
	SerialNumber   string        `bson:"serial_number,nonempty"`
	ValidFrom      bson.DateTime `bson:"valid_from,nonempty"`
	ValidUntil     bson.DateTime `bson:"valid_until,nonempty"`
	Revoked        bool          `bson:"revoked,nonempty"`
	RevocationDate bson.DateTime `bson:"revocation_date,omitempty"`
	RenewalNonces  []int         `bson:"renewal_nonces,omitempty"`
}
