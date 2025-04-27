package hsm

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type Hsm struct {
	Kms       *kms.Client
	RootKeyId *string
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
	if rootKeyId == nil {
		rootKeyId = CreateRootKey(kmsClient)
	}

	return Hsm{
		Kms:       kmsClient,
		RootKeyId: rootKeyId,
	}
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

func (hsm *Hsm) GetPublicKey(keyId *string) []byte {
	publicKeyInput := &kms.GetPublicKeyInput{
		KeyId: keyId,
	}

	publicKeyOutput, err := hsm.Kms.GetPublicKey(context.Background(), publicKeyInput)
	if err != nil {
		fmt.Println("[-] Key does not exist: ", keyId)
		return nil
	}

	return publicKeyOutput.PublicKey
}

func (hsm *Hsm) SignMessage(keyId *string, message []byte, algorithm types.SigningAlgorithmSpec) []byte {
	signInput := &kms.SignInput{
		KeyId:            keyId,
		Message:          message,
		SigningAlgorithm: algorithm,
	}

	signOutput, err := hsm.Kms.Sign(context.Background(), signInput)
	if err != nil {
		log.Fatalf("[-] Unable to sign message: %v", err)
	}

	return signOutput.Signature
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
