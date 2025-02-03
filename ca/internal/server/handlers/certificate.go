package handlers

import (
	"encoding/json"
	"net/http"

	"ca/internal/db"
)

func BuildCertificateHandler() *http.ServeMux {
	router := http.NewServeMux()

	router.HandleFunc("/create", CreateCertificateHandler)

	return router
}

func CreateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Email     string `json:"email"`
		PublicKey string `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	certificate, err := GenerateCertificate(requestBody.Email, []byte(requestBody.PublicKey))
	if err != nil {
		http.Error(w, "Unable to generate certificate", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certificate)
}

func RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		SerialNumber string `json:"serial_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	//Add logic to revoke certificate

	//Response
	response := map[string]string{
		"message": "Certificate revoked successfully",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetCertificateHandler(w http.ResponseWriter, r *http.Request) {
	serialNumber := r.URL.Query().Get("serial_number")
	if serialNumber == "" {
		http.Error(w, "Serial number is required", http.StatusBadRequest)
		return
	}

	certificate, err := db.GetCertificateByID(serialNumber)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certificate)
}

func ValidateCertificate(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Certificate string `json:"certificate"` // Base64 encoded certificate
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// TODO: Validate the certificate (check signature, expiration, revocation status, etc.).
	isValid := true // Placeholder

	response := map[string]any{
		"is_valid": isValid,
		"message":  "Certificate is valid",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetCRL(w http.ResponseWriter, r *http.Request) {
	// TODO: Fetch the current CRL from the database or regenerate it.

	crl := "Current_CR_L_Content" // Placeholder

	response := map[string]string{
		"crl": crl,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RenewCertificate(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		SerialNumber string `json:"serial_number"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// TODO: Verify the certificate's serial number and generate a renewed certificate.
	renewedCertificate := "Renewed_Certificate_Content" // Placeholder

	response := map[string]string{
		"message":     "Certificate renewed successfully",
		"certificate": renewedCertificate,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
