package main

import (
	hsmSvc "ca/internal/hsm"
	"ca/internal/server"
	"context"
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	// Create connection to the HSM
	hsm := hsmSvc.ConnectToHSM()

	// Connect to db
	fmt.Println("[+] Connecting to database...")
	mongoUri := os.Getenv("MONGO_URI")

	// // Loads CA certificate file
	// caCert, err := os.ReadFile("/certs/dev-ca.pem")
	// if err != nil {
	// 	panic(err)
	// }

	// caCertPool := x509.NewCertPool()
	// if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
	// 	panic("Error: CA file must be in PEM format")
	// }

	// // Loads client certificate files
	// cert, err := tls.LoadX509KeyPair("/certs/mongodb.pem", "/certs/mongodb.key")
	// if err != nil {
	// 	panic(err)
	// }

	// Instantiates a Config instance
	// tlsConfig := &tls.Config{
	// 	RootCAs:      caCertPool,
	// 	Certificates: []tls.Certificate{cert},
	// }

	db, err := mongo.Connect(options.Client().ApplyURI(mongoUri))
	if err != nil {
		log.Fatalf("[-] Unable to connect to the database: %v", err)
	}
	fmt.Println("[+] Connected to database.")

	// Close db connection
	defer db.Disconnect(context.Background())

	server.InitServer(&hsm, db)
}
