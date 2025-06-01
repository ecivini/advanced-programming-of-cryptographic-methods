package handlers

import (
	"encoding/json"
	"net/http"
)

// Utility function to handle bad request. It sets the status
// code of the HTTP response and specifies an error message
func ReturnErroredResponse(errorMsg string, w *http.ResponseWriter, statusCode int) {
	response := map[string]string{
		"error": errorMsg,
	}
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(statusCode)
	json.NewEncoder(*w).Encode(response)
}
