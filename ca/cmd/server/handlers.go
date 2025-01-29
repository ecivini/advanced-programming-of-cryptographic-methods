package server

import (
	"net/http"
)

// HealthHandler handles the health check endpoint.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "OK"}`))
}

// SignWithHSMHandler is a placeholder for HSM signing logic.
func SignWithHSMHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "HSM signing not implemented yet"}`))
}
