package handlers

import (
	"net/http"
)

func BuildCertificateHandler() *http.ServeMux {
	router := http.NewServeMux()

	router.HandleFunc("/create", CreateCertificateHandler)

	return router
}

func CreateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Certificate creation not implemented yet"}`))
}
