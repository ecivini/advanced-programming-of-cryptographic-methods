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

func CreateRootKey(hsm *kms.Client) *string {
	// TODO: Discuss the most appropriate key specs
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

	// 6. Sign certificate with KMS
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

func (hsm *Hsm) GetPublicKeyPEM(keyId *string) (string, error) {
	pubKeyDer, err := hsm.GetPublicKey(keyId)
	if err != nil {
		return "", errors.New("Unable to find key with id " + *keyId)
	}

	// Create a PEM block with the public key
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY", // This is the PEM block type
		Bytes: pubKeyDer,    // DER bytes (we don't need to re-encode in this case)
	}

	// Store PEM in a variable (as a string)
	publicKeyPem := pem.EncodeToMemory(pemBlock)

	return string(publicKeyPem), nil
}

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

func (s *HsmECDSASigner) Public() crypto.PublicKey {
	return s.PublicKey
}

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

// The HSM stores only the root CA key
// If there are no keys inside it, it means that
// the CA needs to be set up
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
