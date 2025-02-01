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

// The HSM stores only the root CA key
// If there are no keys inside it, it means that
// the CA needs to be set up
func GetRootKeyId(hsm *kms.Client) *string {
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

	return result.KeyMetadata.KeyId
}

func GetPublicKey(hsm *kms.Client, keyId *string) []byte {
	publicKeyInput := &kms.GetPublicKeyInput{
		KeyId: keyId,
	}

	publicKeyOutput, err := hsm.GetPublicKey(context.Background(), publicKeyInput)
	if err != nil {
		fmt.Println("[-] Key does not exist: ", keyId)
		return nil
	}

	return publicKeyOutput.PublicKey
}

func SignMessage(hsm *kms.Client, keyId *string, message []byte, algorithm types.SigningAlgorithmSpec) []byte {
	signInput := &kms.SignInput{
		KeyId:            keyId,
		Message:          message,
		SigningAlgorithm: algorithm,
	}

	signOutput, err := hsm.Sign(context.Background(), signInput)
	if err != nil {
		log.Fatalf("[-] Unable to sign message: %v", err)
	}

	return signOutput.Signature
}

func ConnectToHSM() *kms.Client {
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

	return kmsClient
}
