package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"ca/internal/config"
	"ca/internal/server/handlers"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// InitServer initializes and starts the HTTP server.
func InitServer(hsmCfg config.HsmConfig) {
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
	certificateRouter := handlers.BuildCertificateHandler()
	mux.Handle("/v1/certificate/", http.StripPrefix("/v1/certificate", certificateRouter))

	infoRouter := handlers.BuildInfoHandler(&hsmCfg)
	mux.Handle("/v1/info/", http.StripPrefix("/v1/info", infoRouter))

	healthRouter := handlers.BuildHealthHandler()
	mux.Handle("/v1/", http.StripPrefix("/v1", healthRouter))

	// Start the server
	serverCfg := config.GetServerConfig()
	fullAddress := serverCfg.Host + ":" + serverCfg.Port

	fmt.Println("[+] Starting CA server on ", fullAddress)
	err = http.ListenAndServe(fullAddress, mux)
	if err != nil {
		log.Fatalf("[-] Failed to start server: %v", err)
	}
}
