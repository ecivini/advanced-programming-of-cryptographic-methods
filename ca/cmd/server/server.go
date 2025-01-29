package server

import (
	"fmt"
	"log"
	"net/http"
)

// InitServer initializes and starts the HTTP server.
func InitServer() {
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/health", HealthHandler)
	mux.HandleFunc("/hsm/sign", SignWithHSMHandler)

	// Start the server
	port := ":3000"
	fmt.Println("Starting CA server on", port)
	err := http.ListenAndServe(port, mux)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
