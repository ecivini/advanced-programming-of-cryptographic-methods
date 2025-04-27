package handlers

import (
	"net/http"
)

type HealthHandler struct{}

func BuildHealthHandler() HealthHandler {
	return HealthHandler{}
}

// HealthHandler handles the health check endpoint.
func (h *HealthHandler) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "OK"}`))
}
