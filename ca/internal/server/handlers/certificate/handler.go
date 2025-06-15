package handlers

import (
	"ca/internal/email"
	"ca/internal/server/handlers"
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
		handlers.ReturnErroredResponse("Invalid request format", &w, http.StatusBadRequest)
		return
	}

	// Validate the email
	if !email.ValidateEmail(requestBody.Email) {
		handlers.ReturnErroredResponse("Provided invalid email", &w, http.StatusBadRequest)
		return
	}
	fmt.Println("[+] Validated email")

	// Validate key type
	if !slices.Contains(SupportedKeyTypes, requestBody.KeyType) {
		handlers.ReturnErroredResponse("Provided invalid key type", &w, http.StatusBadRequest)
		return
	}
	fmt.Println("[+] Validated key type ", requestBody.KeyType)

	// Validate key type
	block, _ := pem.Decode([]byte(requestBody.PublicKeyPEM))
	publicKeyBytes := block.Bytes
	if h.repo.ValidatePublicKey(publicKeyBytes) == nil {
		handlers.ReturnErroredResponse("Provided invalid public key", &w, http.StatusBadRequest)
		return
	}
	fmt.Println("[+] Validated public key")

	// Store commitment
	challenge := h.repo.CreateIdentityCommitment(requestBody.Email, publicKeyBytes, requestBody.KeyType)

	// Send the challenge code by email
	_, err := h.emailService.SendChallengeEmail(requestBody.Email, challenge)
	if err != nil {
		log.Println("Failed to send challenge email: ", err)
		handlers.ReturnErroredResponse("Unable to send email challenge", &w, http.StatusInternalServerError)
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
		handlers.ReturnErroredResponse("Invalid request format", &w, http.StatusBadRequest)
		return
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(requestBody.SignatureB64)
	if err != nil {
		handlers.ReturnErroredResponse("Unable to decode signature", &w, http.StatusBadRequest)
		return
	}

	if requestBody.Challenge == "" {
		handlers.ReturnErroredResponse("Missing challenge parameter", &w, http.StatusBadRequest)
		return
	}

	committedIdentity := h.repo.GetCommitmentFromChallenge(requestBody.Challenge)
	if committedIdentity == nil {
		handlers.ReturnErroredResponse("No identity commitment found", &w, http.StatusBadRequest)
		return
	}

	// Check identity commitment is valid
	now := time.Now()
	if committedIdentity.ValidUntil.Time().Before(now) {
		handlers.ReturnErroredResponse("Identity commitment expired", &w, http.StatusBadRequest)
		return
	}

	challenge, _ := base64.StdEncoding.DecodeString(committedIdentity.Challenge)

	publicKey := h.repo.ValidatePublicKey(committedIdentity.PublicKeyDER)
	if publicKey == nil {
		handlers.ReturnErroredResponse("Unable to validate public key", &w, http.StatusInternalServerError)
		return
	}

	// Verify signature against the raw challenge bytes
	signatureValid := h.repo.verifySignature(challenge, signatureBytes, committedIdentity.PublicKeyDER)
	if !signatureValid {
		handlers.ReturnErroredResponse("Invalid signature", &w, http.StatusBadRequest)
		return
	}

	//Generate certificate
	serialNumber := new(big.Int)
	serialNumber, _ = serialNumber.SetString(committedIdentity.ReservedSerialNumber, 10)
	certificate, err := h.repo.CreateCertificate(committedIdentity.Email, publicKey, serialNumber, nil, nil)
	if err != nil {
		fmt.Println("[-] Unable to create certificate: ", err)
		handlers.ReturnErroredResponse("Failed to generate certificate", &w, http.StatusInternalServerError)
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
		handlers.ReturnErroredResponse("Invalid request payload", &w, http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		handlers.ReturnErroredResponse("Unable to parse signature", &w, http.StatusBadRequest)
		return
	}

	// Retrieve identity commitment based on the serial number
	commitment := h.repo.GetCommitmentFromReservedSerialNumber(requestBody.SerialNumber)
	if commitment == nil {
		handlers.ReturnErroredResponse("Invalid serial number", &w, http.StatusBadRequest)
		return
	}

	// Verify signature
	// Expected message is "Revoke: <serial number>"
	message := []byte("Revoke: " + requestBody.SerialNumber)
	signatureValid := h.repo.verifySignature(message, signature, commitment.PublicKeyDER)
	if !signatureValid {
		handlers.ReturnErroredResponse("Invalid signature", &w, http.StatusBadRequest)
		return
	}

	//Revoke certificate
	if err := h.repo.RevokeCertificate(requestBody.SerialNumber); err != nil {
		handlers.ReturnErroredResponse("Failed to revoke certificate", &w, http.StatusInternalServerError)
		return
	}

	//Response
	response := map[string]string{
		"message": "Certificate revoked successfully",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *CertificateHandler) RenewCertificateHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		handlers.ReturnErroredResponse("Invalid request payload", &w, http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		handlers.ReturnErroredResponse("Unable to parse signature", &w, http.StatusBadRequest)
		return
	}

	// Retrieve identity commitment based on the serial number
	serialNumber := r.PathValue("serial")
	certData := h.repo.GetCertificateDataFromSerialNumber(serialNumber)
	committedIdentity := h.repo.GetCommitmentFromReservedSerialNumber(serialNumber)
	if committedIdentity == nil || certData == nil {
		handlers.ReturnErroredResponse("Invalid serial number", &w, http.StatusBadRequest)
		return
	}

	// Check if the certificate is revoked
	if certData.Revoked {
		handlers.ReturnErroredResponse("Certificate is revoked", &w, http.StatusBadRequest)
		return
	}
	// Check if the certificate is still valid
	now := time.Now()
	if certData.ValidUntil.Time().Before(now) {
		handlers.ReturnErroredResponse("Certificate has expired", &w, http.StatusBadRequest)
		return
	}

	// Verify signature
	// Expected message is "Revoke: <serial number>"
	message := []byte("Renew: " + serialNumber)
	signatureValid := h.repo.verifySignature(message, signature, committedIdentity.PublicKeyDER)
	if !signatureValid {
		handlers.ReturnErroredResponse("Invalid signature", &w, http.StatusBadRequest)
		return
	}

	// Update certificate data in DB
	newExpiryDate := certData.ValidUntil.Time().Add(time.Hour * 24 * 365) // Renew for one year
	if err := h.repo.RenewCertificate(serialNumber, newExpiryDate); err != nil {
		handlers.ReturnErroredResponse("Failed to revoke certificate", &w, http.StatusInternalServerError)
		return
	}

	// Generate new certificate
	serialAsBigInt, _ := new(big.Int).SetString(serialNumber, 10)
	validFrom := certData.ValidFrom.Time()
	certificate, err := h.repo.CreateCertificate(
		committedIdentity.Email,
		h.repo.ValidatePublicKey(committedIdentity.PublicKeyDER),
		serialAsBigInt,
		&validFrom,
		&newExpiryDate,
	)
	if err != nil {
		fmt.Println("[-] Unable to renew certificate: ", err)
		handlers.ReturnErroredResponse("Failed to renew certificate", &w, http.StatusInternalServerError)
		return
	}

	//Response
	response := map[string]string{
		"message":     "Certificate renew successfully",
		"certificate": string(certificate),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *CertificateHandler) GetCertificateStatusHandler(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if serial == "" {
		handlers.ReturnErroredResponse("Serial number is required", &w, http.StatusBadRequest)
		return
	}

	data := h.repo.GetStatusFromSerialNumber(serial)
	if data == nil {
		handlers.ReturnErroredResponse("Certificate not found", &w, http.StatusNotFound)
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
		handlers.ReturnErroredResponse("Invalid page parameter", &w, http.StatusBadRequest)
		return
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("page_size"))
	if err != nil || pageSize < 10 || pageSize > 100 {
		handlers.ReturnErroredResponse("Invalid page_size parameter, must be between 10 and 100", &w, http.StatusBadRequest)
		return
	}

	revokedCertificates, err := h.repo.GetRevokedCertificates(page, pageSize)
	if err != nil {
		fmt.Println("[-] Failed to retrieve revocation list:", err)
		handlers.ReturnErroredResponse("Failed to retrieve revocation list", &w, http.StatusInternalServerError)
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
