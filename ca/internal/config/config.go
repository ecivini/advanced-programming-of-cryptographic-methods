package config

import (
	"os"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type ServerConfig struct {
	Port string
	Host string
}

type HsmConfig struct {
	Hsm       *kms.Client
	RootKeyId string
}

func GetServerConfig() ServerConfig {
	port := GetPort()
	host := GetHost()

	return ServerConfig{
		port,
		host,
	}
}

func GetPort() string {
	port := os.Getenv("CA_PORT")
	if port == "" {
		port = "5000"
	}
	return port
}

func GetHost() string {
	host := os.Getenv("CA_HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	return host
}
