package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

func Connect(uri string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return err
	}

	Client = client
	return nil
}

func SaveIssuedCertificate(cert IssuedCertificate) error {
	collection := Client.Database("ca").Collection("issued_certificates")
	_, err := collection.InsertOne(context.Background(), cert)
	return err
}

func GetCertificateByID(id string) (*IssuedCertificate, error) {
	collection := Client.Database("ca").Collection("issued_certificates")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	var cert IssuedCertificate
	err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&cert)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

func SaveRevokedCertificate(revoked RevocatedCertificate) error {
	collection := Client.Database("ca").Collection("revoked_certificates")
	_, err := collection.InsertOne(context.Background(), revoked)
	return err
}
