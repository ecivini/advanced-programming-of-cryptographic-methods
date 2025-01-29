package handlers

import (
	"net/http"
)

func BuildHealthHandler() *http.ServeMux {
	router := http.NewServeMux()

	router.HandleFunc("/", HealthHandler)

	return router
}

// HealthHandler handles the health check endpoint.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "OK"}`))
}
