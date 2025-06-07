package db

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type IdentityCommitment struct {
	ID                   primitive.ObjectID `bson:"_id,nonempty,unique"`
	Challenge            string             `bson:"challenge,nonempty"`
	Email                string             `bson:"email,nonempty"`
	PublicKeyDER         []byte             `bson:"public_key_der,nonempty"`
	KeyType              string             `bson:"key_type,nonempty"`
	ValidFrom            primitive.DateTime `bson:"valid_from,nonempty"`
	ValidUntil           primitive.DateTime `bson:"valid_until,nonempty"`
	Proof                []byte             `bson:"signature,omitempty"`
	ReservedSerialNumber string             `bson:"reserved_serial_number,unique,nonempty"`
}

type CertificateData struct {
	ID           primitive.ObjectID `bson:"_id,unique,nonempty"`
	SerialNumber string             `bson:"serial_number,nonempty"`
	ValidFrom    primitive.DateTime `bson:"valid_from,nonempty"`
	ValidUntil   primitive.DateTime `bson:"valid_until,nonempty"`
	Revoked      bool               `bson:"revoked,nonempty"`
}
