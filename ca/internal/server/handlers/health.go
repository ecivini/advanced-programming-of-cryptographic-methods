package handlers

import (
	"net/http"
)

type HealthHandler struct{}

func BuildHealthHandler() HealthHandler {
	return HealthHandler{}
}

// HealthCheckHandler performs a health check on the service
// @Summary Health check endpoint
// @Description Returns the current health status of the Certificate Authority service
// @Tags health
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "Service is healthy" example({"status": "OK"})
// @Router /health [get]
func (h *HealthHandler) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "OK"}`))
}
