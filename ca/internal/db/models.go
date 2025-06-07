package db

import (
	"math/big"

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
	ReservedSerialNumber big.Int            `bson:"reserved_serial_number,unique,nonempty"`
}

type CertificateData struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	SerialNumber big.Int            `bson:"challenge,omitempty"`
	ValidFrom    primitive.DateTime `bson:"valid_from,omitempty"`
	ValidUntil   primitive.DateTime `bson:"valid_until,omitempty"`
	Revoked      bool               `bson:"revoked,omitempty"`
}
