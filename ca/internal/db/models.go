package db

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

type IdentityCommitment struct {
	ID                   bson.ObjectID `bson:"_id,nonempty,unique"`
	Challenge            string        `bson:"challenge,nonempty"`
	Email                string        `bson:"email,nonempty"`
	PublicKeyDER         []byte        `bson:"public_key_der,nonempty"`
	KeyType              string        `bson:"key_type,nonempty"`
	ValidFrom            bson.DateTime `bson:"valid_from,nonempty"`
	ValidUntil           bson.DateTime `bson:"valid_until,nonempty"`
	Proof                []byte        `bson:"signature,omitempty"`
	ReservedSerialNumber string        `bson:"reserved_serial_number,unique,nonempty"`
}

type CertificateData struct {
	ID             bson.ObjectID `bson:"_id,unique,nonempty"`
	SerialNumber   string        `bson:"serial_number,nonempty"`
	ValidFrom      bson.DateTime `bson:"valid_from,nonempty"`
	ValidUntil     bson.DateTime `bson:"valid_until,nonempty"`
	Revoked        bool          `bson:"revoked,nonempty"`
	RevocationDate bson.DateTime `bson:"revocation_date,omitempty"`
}
