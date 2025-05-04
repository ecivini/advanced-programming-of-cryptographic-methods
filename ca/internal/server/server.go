package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"ca/internal/config"
	"ca/internal/hsm"
	"ca/internal/server/handlers"
	certificate "ca/internal/server/handlers/certificate"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// InitServer initializes and starts the HTTP server.
func InitServer(hsm *hsm.Hsm) {
	// Connect to db
	fmt.Println("[+] Connecting to database...")
	mongoUri := os.Getenv("MONGO_URI")
	db, err := mongo.Connect(options.Client().ApplyURI(mongoUri))
	if err != nil {
		log.Fatalf("[-] Unable to connect to the database: %v", err)
	}
	fmt.Println("[+] Connected to database.")

	// Close db connection
	defer func() {
		if err = db.Disconnect(context.Background()); err != nil {
			panic(err)
		}
	}()

	// Creating server
	mux := http.NewServeMux()

	// Register handlers
	certificateRepo := certificate.BuildCertificateRepository(hsm, db)
	certificateHandler := certificate.BuildCertificateHandler(certificateRepo)
	mux.HandleFunc("PUT /v1/certificate", certificateHandler.CreateCertificateHandler)
	mux.HandleFunc("POST /v1/certificate/revoke", certificateHandler.RevokeCertificateHandler)
	mux.HandleFunc("GET /v1/certificate/{certId}", certificateHandler.GetCertificateHandler)
	mux.HandleFunc("POST /v1/certificate/validate", certificateHandler.ValidateCertificateHandler)
	mux.HandleFunc("GET /v1/certificate/crl", certificateHandler.GetCRLHandler)
	mux.HandleFunc("POST /v1/certificate/{certId}/renew", certificateHandler.RenewCertificateHandler)

	infoHandler := handlers.BuildInfoHandler(hsm)
	mux.HandleFunc("GET /v1/info/pk", infoHandler.GetRootPublicKeyHandler)

	healthHandler := handlers.BuildHealthHandler()
	mux.HandleFunc("GET /v1/health", healthHandler.HealthCheckHandler)

	// Start the server
	serverCfg := config.GetServerConfig()
	fullAddress := serverCfg.Host + ":" + serverCfg.Port

	fmt.Println("[+] Starting CA server on ", fullAddress)
	err = http.ListenAndServe(fullAddress, mux)
	if err != nil {
		log.Fatalf("[-] Failed to start server: %v", err)
	}
}
