package db

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func StoreIdentityCommitment(client *mongo.Client, commitment IdentityCommitment) error {
	collection := client.Database("ca").Collection("identity_commitments")
	result, err := collection.InsertOne(context.Background(), commitment)
	fmt.Println(result)
	fmt.Println(err)
	return err
}

func RetrieveIdentityCommittment(client *mongo.Client, email string) (*IdentityCommitment, error) {
	fmt.Println("A")
	collection := client.Database("ca").Collection("identity_commitments")
	filter := bson.M{"email": email}
	fmt.Println("B")

	var result IdentityCommitment
	err := collection.FindOne(context.Background(), filter, nil).Decode(&result)

	fmt.Println("C", result, err)
	if err != nil {
		return nil, err
	}

	return &result, nil
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
