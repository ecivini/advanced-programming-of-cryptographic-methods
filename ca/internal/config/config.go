package config

import (
	"os"
)

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
