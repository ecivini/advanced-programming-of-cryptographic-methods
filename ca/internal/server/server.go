package server

import (
	"fmt"
	"log"
	"net/http"

	"ca/internal/config"
	"ca/internal/hsm"
	"ca/internal/server/handlers"
)

// InitServer initializes and starts the HTTP server.
func InitServer() {
	// Create connection to the HSM
	hsm.ConnectToHSM()

	// Creating server
	mux := http.NewServeMux()

	// Register handlers
	certificateRouter := handlers.BuildCertificateHandler()
	mux.Handle("/v1/certificate/", http.StripPrefix("/v1/certificate", certificateRouter))

	healthRouter := handlers.BuildHealthHandler()
	mux.Handle("/v1/", http.StripPrefix("/v1", healthRouter))

	// Start the server
	port := config.GetPort()
	host := config.GetHost()
	fullAddress := host + ":" + port

	fmt.Println("[+] Starting CA server on ", fullAddress)
	err := http.ListenAndServe(fullAddress, mux)
	if err != nil {
		log.Fatalf("[-] Failed to start server: %v", err)
	}
}
