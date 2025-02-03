package handlers

import (
	"encoding/json"
	"net/http"

	"ca/internal/db"
)

func BuildCertificateHandler() *http.ServeMux {
	router := http.NewServeMux()

	router.HandleFunc("/create", CreateCertificateHandler)
	router.HandleFunc("/revoke", RevokeCertificateHandler)
	router.HandleFunc("/get", GetCertificateHandler)
	router.HandleFunc("/validate", ValidateCertificateHandler)
	router.HandleFunc("/crl", GetCRLHandler)
	router.HandleFunc("/renew", RenewCertificateHandler)

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

	//Cenerate certificate
	certificate, err := GenerateCertificate(requestBody.Email, []byte(requestBody.PublicKey))
	if err != nil {
		http.Error(w, "Failed to generate certificate", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certificate)
}

func RevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		SerialNumber string `json:"serial_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	//Revoke certificate
	if err := db.RevokeCertificateByID(requestBody.SerialNumber); err != nil {
		http.Error(w, "Failed to revoke certificate", http.StatusInternalServerError)
		return
	}

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

	//Get certificate
	certificate, err := db.GetCertificateByID(serialNumber)
	if err != nil {
		http.Error(w, "Failed to get certificate", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"certificate": certificate.ID.Hex(), //non va l'id, lo so, è solo un placeholder per fare andare il codice
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func ValidateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Certificate string `json:"certificate"`
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

func GetCRLHandler(w http.ResponseWriter, r *http.Request) {

	crl, err := db.GetCRL()
	if err != nil {
		http.Error(w, "Failed to get CRL", http.StatusInternalServerError)
		return
	}

	crlJSON, err := json.Marshal(crl)
	if err != nil {
		http.Error(w, "Failed to marshal CRL", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"crl": string(crlJSON),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RenewCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		SerialNumber string `json:"serial_number"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// TODO: Generate a renewed certificate
	if err := db.RevokeCertificateByID(requestBody.SerialNumber); err != nil {
		http.Error(w, "Failed to renew certificate", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "Certificate renewed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
