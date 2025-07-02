package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func StoreIdentityCommitment(client *mongo.Client, commitment IdentityCommitment) error {
	collection := client.Database("ca").Collection("identity_commitments")
	_, err := collection.InsertOne(context.Background(), commitment)

	return err
}

func RetrieveIdentityCommittment(client *mongo.Client, challenge string) (*IdentityCommitment, error) {
	collection := client.Database("ca").Collection("identity_commitments")
	filter := bson.M{"challenge": challenge}

	var result IdentityCommitment
	err := collection.FindOne(context.Background(), filter, nil).Decode(&result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func RetrieveIdentityCommittmentFromReservedSerial(client *mongo.Client, serial string) (*IdentityCommitment, error) {
	collection := client.Database("ca").Collection("identity_commitments")
	filter := bson.M{"reserved_serial_number": serial}

	var result IdentityCommitment
	err := collection.FindOne(context.Background(), filter, nil).Decode(&result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func RetrieveCertificateDataFromSerial(client *mongo.Client, serial string) (*CertificateData, error) {
	collection := client.Database("ca").Collection("certificates_data")
	filter := bson.M{"serial_number": serial}

	var result CertificateData
	err := collection.FindOne(context.Background(), filter, nil).Decode(&result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func StoreCertificateData(client *mongo.Client, certData CertificateData) error {
	collection := client.Database("ca").Collection("certificates_data")
	_, err := collection.InsertOne(context.Background(), certData)

	return err
}

func RetrieveCertificateData(client *mongo.Client, serial string) (*CertificateData, error) {
	collection := client.Database("ca").Collection("certificates_data")
	filter := bson.M{"serial_number": serial}

	var result CertificateData
	err := collection.FindOne(context.Background(), filter, nil).Decode(&result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func RevokeCertificate(client *mongo.Client, serial string) error {
	collection := client.Database("ca").Collection("certificates_data")

	filter := bson.M{"serial_number": serial}
	update := bson.M{"$set": bson.M{"revoked": true, "revocation_date": bson.NewDateTimeFromTime(time.Now())}}

	result, err := collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments
	}

	return nil
}

func StoreIdentityCommitmentChallengeProof(client *mongo.Client, challenge string, proof []byte) error {
	collection := client.Database("ca").Collection("identity_commitments")

	filter := bson.M{"challenge": challenge}
	update := bson.M{"$set": bson.M{"proof": proof}}

	result, err := collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments
	}

	return nil
}

func RenewCertificate(client *mongo.Client, serial string, newExpiryDate time.Time, updatedUsedNonces []int) error {
	collection := client.Database("ca").Collection("certificates_data")

	filter := bson.M{"serial_number": serial}
	update := bson.M{"$set": bson.M{"valid_until": bson.NewDateTimeFromTime(newExpiryDate), "renewal_nonces": updatedUsedNonces}}

	result, err := collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return mongo.ErrNoDocuments
	}

	return nil
}

func GetRevokedCertificates(client *mongo.Client, page, pageSize int) ([]CertificateData, error) {
	collection := client.Database("ca").Collection("certificates_data")
	filter := bson.M{"revoked": true}

	skip := (page - 1) * pageSize
	limit := pageSize
	opts := options.Find().SetSkip(int64(skip)).SetLimit(int64(limit))

	cursor, err := collection.Find(context.Background(), filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	var revokedCerts []CertificateData
	err = cursor.All(context.Background(), &revokedCerts)
	if err != nil {
		return nil, err
	}

	return revokedCerts, nil
}

// func SaveIssuedCertificate(cert IssuedCertificate) error {
// 	collection := Client.Database("ca").Collection("issued_certificates")
// 	_, err := collection.InsertOne(context.Background(), cert)
// 	return err
// }

// func GetCertificateByID(id string) (*IssuedCertificate, error) {
// 	collection := Client.Database("ca").Collection("issued_certificates")
// 	objID, err := primitive.ObjectIDFromHex(id)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var cert IssuedCertificate
// 	err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&cert)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &cert, nil
// }

// func SaveRevokedCertificate(revoked RevocatedCertificate) error {
// 	collection := Client.Database("ca").Collection("revoked_certificates")
// 	_, err := collection.InsertOne(context.Background(), revoked)
// 	return err
// }

// func GetRevokedCertificateByID(id string) (*RevocatedCertificate, error) {
// 	collection := Client.Database("ca").Collection("revoked_certificates")
// 	objID, err := primitive.ObjectIDFromHex(id)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var revoked RevocatedCertificate
// 	err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&revoked)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &revoked, nil
// }

// func RevokeCertificateByID(serialNumber string) error {
// 	collection := Client.Database("ca").Collection("issued_certificates")
// 	_, err :=
// 		collection.UpdateOne(
// 			context.Background(),
// 			bson.M{"certificate_id": serialNumber},
// 			bson.M{"$set": bson.M{"revocation_date": time.Now().Format(time.RFC3339)}},
// 		)
// 	return err
// }

// func GetCRL() ([]RevocatedCertificate, error) {
// 	collection := Client.Database("ca").Collection("revoked_certificates")
// 	cursor, err := collection.Find(context.Background(), bson.M{})
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer cursor.Close(context.Background())

// 	var revoked []RevocatedCertificate
// 	if err = cursor.All(context.Background(), &revoked); err != nil {
// 		return nil, err
// 	}

// 	return revoked, nil
// }

// func RenewCertificate(serialNumber string) error {
// 	collection := Client.Database("ca").Collection("issued_certificates")
// 	_, err :=
// 		collection.UpdateOne(
// 			context.Background(),
// 			bson.M{"certificate_id": serialNumber},
// 			bson.M{"$set": bson.M{"valid_from": time.Now().Format(time.RFC3339)}},
// 		)
// 	return err
// }
