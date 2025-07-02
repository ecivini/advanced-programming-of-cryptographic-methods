package hsm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type Hsm struct {
	Kms       *kms.Client
	RootKeyId *string
}

type HsmECDSASigner struct {
	Hsm        *Hsm
	PublicKey  crypto.PublicKey
	SigningAlg types.SigningAlgorithmSpec
	Context    context.Context
}

// ConnectToHSM establishes a connection to the AWS KMS Hardware Security Module and initializes the CA.
// This function performs the complete HSM setup process including AWS configuration, KMS client creation,
// root key management, and root certificate generation if needed.
//
// Required Environment Variables:
//   - AWS_REGION: AWS region where the KMS service is located
//   - KMS_ENDPOINT: Custom KMS endpoint URL (for LocalStack or custom deployments)
//   - AWS credentials (via standard AWS credential chain)
//
// Returns:
//   - Hsm: Configured HSM instance with established KMS connection and root key reference
//
// Panics:
//   - If AWS configuration cannot be loaded
//   - If KMS connection fails
//   - If root key creation fails
func ConnectToHSM() Hsm {
	fmt.Println("[+] Connecting to HSM ...")

	// Loads credentials from the environment variables
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(os.Getenv("AWS_REGION")),
	)

	if err != nil {
		log.Fatalf("[-] Unable to load SDK config, %v", err)
	}

	kmsClient := kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(os.Getenv("KMS_ENDPOINT"))
	})

	fmt.Println("[+] Connected successfully to HSM.")

	rootKeyId := getRootKeyId(kmsClient)
	shouldCreateRootCertificate := false
	if rootKeyId == nil {
		rootKeyId = CreateRootKey(kmsClient)

		shouldCreateRootCertificate = true
	}

	hsm := Hsm{
		Kms:       kmsClient,
		RootKeyId: rootKeyId,
	}

	if shouldCreateRootCertificate {
		hsm.CreateRootCertificate()
	}

	return hsm
}

// CreateRootKey generates a new root CA key in AWS KMS for certificate signing operations.
// This function creates an ECC NIST P-256 key specifically configured for signing and verification,
// which serves as the root private key for the entire Certificate Authority infrastructure.
//
// Parameters:
//   - hsm: AWS KMS client instance for key creation operations
//
// Returns:
//   - *string: Pointer to the unique KMS key identifier for the created root key
//
// Key Specifications:
//   - Key Type: ECC NIST P-256 (Elliptic Curve Cryptography)
//   - Key Usage: Sign/Verify operations only
//   - Description: "CA ROOT KEY" for identification purposes
//
// Panics:
//   - If key creation fails due to KMS service errors or permission issues
func CreateRootKey(hsm *kms.Client) *string {
	keySpecs := &kms.CreateKeyInput{
		Description: aws.String("CA ROOT KEY"),
		KeyUsage:    types.KeyUsageTypeSignVerify,
		KeySpec:     types.KeySpecEccNistP256,
	}

	result, err := hsm.CreateKey(context.Background(), keySpecs)
	if err != nil {
		log.Fatalf("[-] Failed to create root CA key: %v", err)
	}
	fmt.Println("[+] Root key id: ", *result.KeyMetadata.KeyId)

	return result.KeyMetadata.KeyId
}

// CreateRootCertificate generates and stores the self-signed root CA certificate.
//
// The function performs the following operations:
//  1. Creates an ECDSA signer using the HSM-stored root key
//  2. Constructs a self-signed X.509 certificate with CA capabilities
//  3. Signs the certificate using the HSM root key
//  4. Saves the certificate to /certs/root.pem in PEM format
//
// Panics:
//   - If ECDSA signer creation fails
//   - If certificate generation fails
//   - If file system operations fail
func (hsm *Hsm) CreateRootCertificate() {
	// Create signer
	signer, err := hsm.BuildECDSASigner(context.Background())
	if err != nil {
		log.Fatalf("[-] Unable to create ECDSA signer: %s", err)
	}

	now := time.Now()
	oneYearFromNow := now.Add(time.Hour * 24 * 365)

	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             now,
		NotAfter:              oneYearFromNow,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Sign certificate with KMS
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		rootCert,
		rootCert,
		signer.PublicKey,
		signer,
	)
	if err != nil {
		log.Fatalf("[-] Unable to create root certificate: %s", err)
	}

	// 7. Output the PEM certificate
	rootCertFile, err := os.OpenFile("/certs/root.pem", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalf("[-] Unable to store root certificate: %s", err)
	}
	defer rootCertFile.Close()

	pem.Encode(rootCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// GetPublicKeyPEM retrieves the public key from KMS and returns it in PEM format.
// This method provides access to the public key material corresponding to a KMS-stored
// private key, formatted as a standard PEM-encoded public key for distribution and use.
//
// Parameters:
//   - keyId: Pointer to the KMS key identifier whose public key should be retrieved
//
// Returns:
//   - string: PEM-encoded public key string ready for distribution or storage
//   - error: nil on success, or error if key retrieval or encoding fails
func (hsm *Hsm) GetPublicKeyPEM(keyId *string) (string, error) {
	pubKeyDer, err := hsm.GetPublicKey(keyId)
	if err != nil {
		return "", errors.New("Unable to find key with id " + *keyId)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDer,
	}

	publicKeyPem := pem.EncodeToMemory(pemBlock)

	return string(publicKeyPem), nil
}

// GetPublicKey retrieves the raw DER-encoded public key bytes from AWS KMS.
// This method provides access to the binary public key material in DER format,
// which can be used for cryptographic operations or further encoding.
//
// Parameters:
//   - keyId: Pointer to the KMS key identifier whose public key should be retrieved
//
// Returns:
//   - []byte: DER-encoded public key bytes, or empty slice if key doesn't exist
//   - error: nil on success, or error if KMS operation fails
func (hsm *Hsm) GetPublicKey(keyId *string) ([]byte, error) {
	publicKeyInput := &kms.GetPublicKeyInput{
		KeyId: keyId,
	}

	publicKeyOutput, err := hsm.Kms.GetPublicKey(context.Background(), publicKeyInput)
	if err != nil {
		fmt.Println("[-] Key does not exist: ", keyId)
		return []byte{}, nil
	}

	return publicKeyOutput.PublicKey, nil
}

// BuildECDSASigner creates a crypto.Signer implementation that uses AWS KMS for ECDSA operations.
// This method constructs a signer that implements the standard Go crypto.Signer interface
// while delegating all private key operations to the Hardware Security Module.
//
// Parameters:
//   - ctx: Context for controlling the lifecycle of KMS operations
//
// Returns:
//   - *HsmECDSASigner: Configured signer that implements crypto.Signer interface
//   - error: nil on success, or error if key retrieval, parsing, or validation fails
//
// The returned signer:
//   - Uses ECDSA-SHA256 signing algorithm
//   - Delegates all private key operations to KMS
func (hsm *Hsm) BuildECDSASigner(ctx context.Context) (*HsmECDSASigner, error) {
	pubResp, err := hsm.Kms.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(*hsm.RootKeyId),
	})
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubResp.PublicKey)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("KMS key is not ECDSA")
	}

	return &HsmECDSASigner{
		Hsm:        hsm,
		PublicKey:  ecdsaKey,
		SigningAlg: types.SigningAlgorithmSpecEcdsaSha256,
		Context:    ctx,
	}, nil
}

// Public returns the public key associated with this HSM signer.
// This method implements the crypto.Signer interface requirement to provide
// access to the public key corresponding to the private key stored in the HSM.
//
// Returns:
//   - crypto.PublicKey: The public key that corresponds to the HSM-stored private key
func (s *HsmECDSASigner) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign performs ECDSA-SHA256 digital signature operations using the HSM-stored private key.
//
// Parameters:
//   - rand: Random number generator
//   - digest: Pre-computed hash digest to be signed (must be SHA-256)
//   - opts: Signing options
//
// Returns:
//   - []byte: DER-encoded ECDSA signature bytes
//   - error: nil on success, or error if KMS signing operation fails
//
// The returned signature is in DER format and can be used directly with
// standard Go cryptographic libraries and X.509 certificate operations.
func (s *HsmECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signOut, err := s.Hsm.Kms.Sign(s.Context, &kms.SignInput{
		KeyId:            aws.String(*s.Hsm.RootKeyId),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.SigningAlg,
	})
	if err != nil {
		return nil, err
	}

	return signOut.Signature, nil
}

// getRootKeyId searches for and returns the identifier of the root CA key in KMS.
// This internal function implements the key discovery logic for determining whether
// a root CA key already exists or if a new CA setup is required.
//
// Parameters:
//   - hsm: AWS KMS client instance for listing and querying keys
//
// Returns:
//   - *string: Pointer to the root key identifier if found, nil if no keys exist
//
// Panics:
//   - If KMS key listing operation fails due to service errors or permissions
func getRootKeyId(hsm *kms.Client) *string {
	output, err := hsm.ListKeys(context.Background(), &kms.ListKeysInput{})
	if err != nil {
		log.Fatalf("[-] Failed to list KMS keys: %v", err)
	}

	numberOfKeys := len(output.Keys)
	if numberOfKeys == 0 {
		return nil
	}

	keyId := output.Keys[0].KeyId

	return keyId
}
