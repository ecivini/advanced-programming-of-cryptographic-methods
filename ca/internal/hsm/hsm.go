package hsm

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func ConnectToHSM() *kms.Client {
	fmt.Println("[+] Connecting to HSM ...")

	// Loads credentials from the environment variables
	cfg, err := config.LoadDefaultConfig(context.TODO(),
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
