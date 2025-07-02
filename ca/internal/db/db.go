package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// StoreIdentityCommitment stores a new identity commitment in the database.
// An identity commitment represents a user's initial request to obtain a certificate,
// containing their public key and email information along with a generated challenge.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - commitment: IdentityCommitment struct containing user's public key, email, and challenge
//
// Returns:
//   - error: nil on success, or the error that occurred during the database operation
func StoreIdentityCommitment(client *mongo.Client, commitment IdentityCommitment) error {
	collection := client.Database("ca").Collection("identity_commitments")
	_, err := collection.InsertOne(context.Background(), commitment)

	return err
}

// RetrieveIdentityCommittment retrieves an identity commitment from the database using a challenge string.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - challenge: The unique challenge string associated with the identity commitment, encoded in base64
//
// Returns:
//   - *IdentityCommitment: Pointer to the found identity commitment, or nil if not found
//   - error: nil on success, mongo.ErrNoDocuments if not found, or other database errors
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

// RetrieveIdentityCommittmentFromReservedSerial retrieves an identity commitment using a reserved serial number.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - serial: The reserved serial number associated with the identity commitment
//
// Returns:
//   - *IdentityCommitment: Pointer to the found identity commitment, or nil if not found
//   - error: nil on success, mongo.ErrNoDocuments if not found, or other database errors
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

// RetrieveCertificateDataFromSerial retrieves certificate data from the database using a serial number.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - serial: The unique serial number of the certificate to retrieve
//
// Returns:
//   - *CertificateData: Pointer to the found certificate data, or nil if not found
//   - error: nil on success, mongo.ErrNoDocuments if not found, or other database errors
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

// StoreCertificateData stores certificate data in the database after successful certificate issuance.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - certData: CertificateData struct containing all certificate information to be stored
//
// Returns:
//   - error: nil on success, or the error that occurred during the database operation
func StoreCertificateData(client *mongo.Client, certData CertificateData) error {
	collection := client.Database("ca").Collection("certificates_data")
	_, err := collection.InsertOne(context.Background(), certData)

	return err
}

// RetrieveCertificateData retrieves certificate data from the database using a serial number.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - serial: The unique serial number of the certificate to retrieve
//
// Returns:
//   - *CertificateData: Pointer to the found certificate data, or nil if not found
//   - error: nil on success, mongo.ErrNoDocuments if not found, or other database errors
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

// RevokeCertificate marks a certificate as revoked in the database and sets the revocation timestamp.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - serial: The unique serial number of the certificate to revoke
//
// Returns:
//   - error: nil on success, mongo.ErrNoDocuments if certificate not found, or other database errors
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

// StoreIdentityCommitmentChallengeProof updates an identity commitment with cryptographic proof.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - challenge: The unique challenge string that identifies the commitment
//   - proof: The cryptographic proof (signature) demonstrating private key possession
//
// Returns:
//   - error: nil on success, mongo.ErrNoDocuments if commitment not found, or other database errors
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

// RenewCertificate extends the validity period of an existing certificate.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - serial: The unique serial number of the certificate to renew
//   - newExpiryDate: The new expiration date for the renewed certificate
//   - updatedUsedNonces: Array of nonces used in renewal requests to prevent replay attacks
//
// Returns:
//   - error: nil on success, mongo.ErrNoDocuments if certificate not found, or other database errors
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

// GetRevokedCertificates retrieves a paginated list of all revoked certificates from the database.
//
// Parameters:
//   - client: MongoDB client instance for database operations
//   - page: The page number for pagination (1-based indexing)
//   - pageSize: The number of certificates to return per page
//
// Returns:
//   - []CertificateData: Slice of revoked certificate data, empty if no revoked certificates found
//   - error: nil on success, or the error that occurred during the database operation
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
