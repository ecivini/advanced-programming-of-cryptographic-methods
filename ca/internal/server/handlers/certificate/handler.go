package handlers

import (
	"ca/internal/email"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"time"
)

var SupportedKeyTypes = []string{
	"ECDSA",
	"RSA_2048",
	"RSA_4096",
}

type CertificateHandler struct {
	repo         CertificateRepository
	emailService *email.EmailService
}

func BuildCertificateHandler(repo CertificateRepository, email *email.EmailService) CertificateHandler {
	return CertificateHandler{
		repo:         repo,
		emailService: email,
	}
}

// TODO: Refactor into proper sub functions and modules
func (h *CertificateHandler) CommitIdentityHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Email        string `json:"email"`
		PublicKeyPEM string `json:"public_key"`
		KeyType      string `json:"key_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		response := map[string]string{
			"error": "Invalid request format",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate the email
	if !email.ValidateEmail(requestBody.Email) {
		response := map[string]string{
			"error": "Provided invalid email.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}
	fmt.Println("[+] Validated email")

	// Validate key type
	if !slices.Contains(SupportedKeyTypes, requestBody.KeyType) {
		response := map[string]string{
			"error": "Provided invalid key_type.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}
	fmt.Println("[+] Validated key type ", requestBody.KeyType)

	// Validate key type
	block, _ := pem.Decode([]byte(requestBody.PublicKeyPEM))
	publicKeyBytes := block.Bytes
	if h.repo.ValidatePublicKey(publicKeyBytes) == nil {
		fmt.Println("[-] Error while parsing public key")
		response := map[string]string{
			"error": "Provided invalid public_key." + string(publicKeyBytes), // For debugging purposes
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}
	fmt.Println("[+] Validated public key")

	if !slices.Contains(SupportedKeyTypes, requestBody.KeyType) {
		response := map[string]string{
			"error": "Provided invalid key_type.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Store commitment
	challenge := h.repo.CreateIdentityCommitment(requestBody.Email, publicKeyBytes, requestBody.KeyType)

	// Send the challenge code by email
	_, err := h.emailService.SendChallengeEmail(requestBody.Email, challenge)
	if err != nil {
		log.Printf("Failed to send challenge email: %v", err)
		http.Error(w, "could not send challenge email", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// TODO: Refactor
func (h *CertificateHandler) CreateCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		SignatureB64 string `json:"signature"`
		Challenge    string `json:"challenge"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		response := map[string]string{
			"error": "Invalid request format",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(requestBody.SignatureB64)
	if err != nil {
		response := map[string]string{
			"error": "Unable to decode signature",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	if requestBody.Challenge == "" {
		response := map[string]string{
			"error": "Missing challenge parameter",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	committedIdentity := h.repo.GetCommitmentFromChallenge(requestBody.Challenge)
	if committedIdentity == nil {
		response := map[string]string{
			"error": "No identity commitment found",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check identity commitment is valid
	now := time.Now()
	if committedIdentity.ValidUntil.Time().Before(now) {
		response := map[string]string{
			"error": "Commited identity expired",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	challenge, _ := base64.StdEncoding.DecodeString(committedIdentity.Challenge)

	publicKey := h.repo.ValidatePublicKey(committedIdentity.PublicKeyDER)
	if publicKey == nil {
		panic("[-] Already stored public key is invalid.")
	}

	// Verify signature - the challenge from the user should match the stored challenge
	// The challenge parameter should be the base64 challenge, not decoded
	if requestBody.Challenge != committedIdentity.Challenge {
		response := map[string]string{
			"error": "Challenge mismatch",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify signature against the raw challenge bytes
	signatureValid := h.repo.verifySignature(challenge, signatureBytes, committedIdentity.PublicKeyDER)
	if !signatureValid {
		response := map[string]string{
			"error": "Invalid signature",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	//Generate certificate
	serialNumber := new(big.Int)
	serialNumber, _ = serialNumber.SetString(committedIdentity.ReservedSerialNumber, 10)
	certificate, err := h.repo.CreateCertificate(committedIdentity.Email, publicKey, serialNumber)
	if err != nil {
		fmt.Printf("[-] Unable to create certificate: %s\n", err)
		http.Error(w, "Failed to generate certificate", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"certificate": string(certificate),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (h *CertificateHandler) RevokeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		SerialNumber string `json:"serial_number"`
		Signature    string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		http.Error(w, "Unable to parse signature", http.StatusBadRequest)
		return
	}

	// Retrieve identity commitment based on the serial number
	commitment := h.repo.GetCommitmentFromReservedSerialNumber(requestBody.SerialNumber)
	if commitment == nil {
		http.Error(w, "Invalid serial number", http.StatusBadRequest)
		return
	}

	// Verify signature
	// Expected message is "Revoke: <serial number>"
	message := []byte("Revoke: " + requestBody.SerialNumber)
	signatureValid := h.repo.verifySignature(message, signature, commitment.PublicKeyDER)
	if !signatureValid {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	//Revoke certificate
	if err := h.repo.RevokeCertificateByID(requestBody.SerialNumber); err != nil {
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

func (h *CertificateHandler) GetCertificateStatusHandler(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if serial == "" {
		http.Error(w, "Serial number is required", http.StatusBadRequest)
		return
	}

	data := h.repo.GetStatusFromSerialNumber(serial)
	if data == nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}
	response := map[string]bool{
		"revoked": data.Revoked,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *CertificateHandler) GetRevocationListHandler(w http.ResponseWriter, r *http.Request) {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		http.Error(w, "Invalid page parameter", http.StatusBadRequest)
		return
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("page_size"))
	if err != nil || pageSize < 10 || pageSize > 100 {
		http.Error(w, "Invalid page_size parameter, must be between 10 and 100", http.StatusBadRequest)
		return
	}

	revokedCertificates, err := h.repo.GetRevokedCertificates(page, pageSize)
	if err != nil {
		fmt.Println("[-] Failed to retrieve revocation list:", err)
		http.Error(w, "Failed to retrieve revocation list", http.StatusInternalServerError)
		return
	}
	response := make([]map[string]string, len(revokedCertificates))
	for i, cert := range revokedCertificates {
		response[i] = map[string]string{
			"serial_number":   cert.SerialNumber,
			"revocation_date": cert.RevocationDate.Time().Format(time.RFC3339),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// func (h *CertificateHandler) GetCertificateHandler(w http.ResponseWriter, r *http.Request) {
// 	certSerialNumber := r.PathValue("certId")
// 	// if certSerialNumber == "" {
// 	// 	http.Error(w, "Serial number is required", http.StatusBadRequest)
// 	// 	return
// 	// }

// 	//Get certificate
// 	certificate, err := db.GetCertificateByID(certSerialNumber)
// 	if err != nil {
// 		http.Error(w, "Failed to get certificate", http.StatusInternalServerError)
// 		return
// 	}

// 	response := map[string]string{
// 		"certificate": certificate.ID.Hex(), //non va l'id, lo so, è solo un placeholder per fare andare il codice
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }

// func (h *CertificateHandler) ValidateCertificateHandler(w http.ResponseWriter, r *http.Request) {
// 	var requestBody struct {
// 		Certificate string `json:"certificate"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
// 		http.Error(w, "Invalid request payload", http.StatusBadRequest)
// 		return
// 	}

// 	// TODO: Validate the certificate (check signature, expiration, revocation status, etc.).
// 	isValid := true // Placeholder

// 	response := map[string]any{
// 		"is_valid": isValid,
// 		"message":  "Certificate is valid",
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }

// func (h *CertificateHandler) GetCRLHandler(w http.ResponseWriter, r *http.Request) {

// 	crl, err := db.GetCRL()
// 	if err != nil {
// 		http.Error(w, "Failed to get CRL", http.StatusInternalServerError)
// 		return
// 	}

// 	crlJSON, err := json.Marshal(crl)
// 	if err != nil {
// 		http.Error(w, "Failed to marshal CRL", http.StatusInternalServerError)
// 		return
// 	}

// 	response := map[string]string{
// 		"crl": string(crlJSON),
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }

// func (h *CertificateHandler) RenewCertificateHandler(w http.ResponseWriter, r *http.Request) {
// 	certSerialNumber := r.PathValue("certId")

// 	// TODO: Generate a renewed certificate
// 	if err := db.RevokeCertificateByID(certSerialNumber); err != nil {
// 		http.Error(w, "Failed to renew certificate", http.StatusInternalServerError)
// 		return
// 	}

// 	response := map[string]string{
// 		"message": "Certificate renewed successfully",
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }
