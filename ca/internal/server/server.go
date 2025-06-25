package server

import (
	"fmt"
	"log"
	"net/http"

	"github.com/rs/cors"

	"ca/internal/config"
	"ca/internal/email"
	"ca/internal/hsm"
	"ca/internal/server/handlers"
	certificate "ca/internal/server/handlers/certificate"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// InitServer initializes and starts the HTTP server.
func InitServer(hsm *hsm.Hsm, db *mongo.Client, emailService *email.EmailService) {

	// Creating server
	mux := http.NewServeMux()

	// Register handlers
	certificateRepo := certificate.BuildCertificateRepository(hsm, db)
	certificateHandler := certificate.BuildCertificateHandler(certificateRepo, emailService)
	mux.HandleFunc("PUT /v1/identity", certificateHandler.CommitIdentityHandler)
	mux.HandleFunc("PUT /v1/certificate", certificateHandler.CreateCertificateHandler)
	mux.HandleFunc("POST /v1/certificate/{serial}/revoke", certificateHandler.RevokeCertificateHandler)
	// TODO: Remove old GET endpoint
	// Support both GET (legacy) and POST (with nonce) for certificate status
	// mux.HandleFunc("GET /v1/certificate/{serial}/status", certificateHandler.GetCertificateStatusHandler)
	mux.HandleFunc("GET /v1/certificate/status", certificateHandler.GetCertificateStatusHandler)
	mux.HandleFunc("POST /v1/certificate/{serial}/renew", certificateHandler.RenewCertificateHandler)
	// Support both GET and POST for revocation list
	mux.HandleFunc("GET /v1/crl", certificateHandler.GetRevocationListHandler)

	infoHandler := handlers.BuildInfoHandler(hsm)
	mux.HandleFunc("GET /v1/info/pk", infoHandler.GetRootPublicKeyHandler)

	healthHandler := handlers.BuildHealthHandler()
	mux.HandleFunc("GET /v1/health", healthHandler.HealthCheckHandler)

	// Start the server
	serverCfg := config.GetServerConfig()
	fullAddress := serverCfg.Host + ":" + serverCfg.Port

	fmt.Println("[+] Starting CA server on ", fullAddress)
	corsHandler := cors.AllowAll().Handler(mux)
	err := http.ListenAndServe(fullAddress, corsHandler)
	if err != nil {
		log.Fatalf("[-] Failed to start server: %v", err)
	}
}
