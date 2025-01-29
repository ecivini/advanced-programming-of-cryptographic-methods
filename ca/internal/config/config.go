package config

import (
	"os"
)

// GetPort retrieves the server port from the environment or defaults to 3000.
func GetPort() string {
	port := os.Getenv("CA_PORT")
	if port == "" {
		port = "5000"
	}
	return ":" + port
}
