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
	"os"
	"time"
)

type CertificateHandler struct {
	repo         CertificateRepository
	emailService *email.EmailService
	// Add components for signed responses and replay protection
	responseSigner *ResponseSigner
	nonceManager   *NonceManager
}

func BuildCertificateHandler(repo CertificateRepository, email *email.EmailService) CertificateHandler {
	// Initialize response signer and nonce manager
	responderId := os.Getenv("CA_RESPONDER_ID")
	if responderId == "" {
		log.Fatal("CA_RESPONDER_ID environment variable is not set")
	}
	responseSigner := NewResponseSigner(repo.hsm, responderId)
	nonceManager := NewNonceManager()

	return CertificateHandler{
		repo:           repo,
		emailService:   email,
		responseSigner: responseSigner,
		nonceManager:   nonceManager,
	}
}

// TODO: Refactor into proper sub functions and modules
func (h *CertificateHandler) CommitIdentityHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		Email        string `json:"email"`
		PublicKeyPEM string `json:"public_key"`
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

	// Validate key
	block, _ := pem.Decode([]byte(requestBody.PublicKeyPEM))
	publicKeyBytes := block.Bytes
	if h.repo.ValidatePublicKey(publicKeyBytes) == nil {
		handlers.ReturnErroredResponse("Provided invalid public key", &w, http.StatusBadRequest)
		return
	}
	fmt.Println("[+] Validated public key")

	// Store commitment
	challenge := h.repo.CreateIdentityCommitment(requestBody.Email, publicKeyBytes)

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

	const genericErrorMessage = "Unable to generate certificate"

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		handlers.ReturnErroredResponse("Invalid request format", &w, http.StatusBadRequest)
		return
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(requestBody.SignatureB64)
	if err != nil {
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	if requestBody.Challenge == "" {
		handlers.ReturnErroredResponse("Missing challenge parameter", &w, http.StatusBadRequest)
		return
	}

	committedIdentity := h.repo.GetCommitmentFromChallenge(requestBody.Challenge)
	if committedIdentity == nil {
		log.Println("[-] Unable to retrieve identity commitment for challenge: ", requestBody.Challenge)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Check identity commitment is valid
	now := time.Now()
	if committedIdentity.ValidUntil.Time().Before(now) {
		log.Println("[-] Identity commitment expired for challenge: ", requestBody.Challenge)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Check if challenge has been used
	if committedIdentity.Proof != nil {
		log.Println("[-] Challenge already used for challenge: ", requestBody.Challenge)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	challenge, _ := base64.StdEncoding.DecodeString(committedIdentity.Challenge)

	publicKey := h.repo.ValidatePublicKey(committedIdentity.PublicKeyDER)
	if publicKey == nil {
		log.Println("[-] Invalid public key for challenge: ", requestBody.Challenge)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
		return
	}

	// Verify signature against the raw challenge bytes
	signatureValid := h.repo.verifySignature(challenge, signatureBytes, committedIdentity.PublicKeyDER)
	if !signatureValid {
		log.Printf("[-] Invalid signature [%s] for challenge: %s", requestBody.SignatureB64, requestBody.Challenge)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}
	// Store signature so that it is passed to CreateCertificate
	committedIdentity.Proof = signatureBytes

	//Generate certificate
	serialNumber := new(big.Int)
	serialNumber, _ = serialNumber.SetString(committedIdentity.ReservedSerialNumber, 10)
	certificate, err := h.repo.CreateCertificate(committedIdentity, publicKey, serialNumber, nil, nil)
	if err != nil {
		fmt.Println("[-] Unable to create certificate: ", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
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
		Signature    string `json:"signature"`
		SerialNumber string `json:"serial_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		handlers.ReturnErroredResponse("Invalid request payload", &w, http.StatusBadRequest)
		return
	}

	const genericErrorMessage = "Unable to revoke certificate"
	signature, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		log.Println("[-] Unable to parse signature: ", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Retrieve identity commitment based on the serial number
	serialNumber := requestBody.SerialNumber
	commitment := h.repo.GetCommitmentFromReservedSerialNumber(serialNumber)
	if commitment == nil {
		log.Println("[-] Unable to retrieve identity commitment for serial number: ", serialNumber)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Check if the certificate is already revoked
	if h.repo.IsCertificateRevoked(serialNumber) {
		log.Println("[-] Certificate is already revoked for serial number: ", serialNumber)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Verify signature
	// Expected message is "Revoke: <serial number>"
	message := []byte("Revoke: " + serialNumber)
	signatureValid := h.repo.verifySignature(message, signature, commitment.PublicKeyDER)
	if !signatureValid {
		log.Println("[-] Invalid signature for serial number: ", serialNumber)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	//Revoke certificate
	if err := h.repo.RevokeCertificate(serialNumber); err != nil {
		log.Println("[-] Failed to revoke certificate: ", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
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
		Signature    string `json:"signature"`
		SerialNumber string `json:"serial_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		handlers.ReturnErroredResponse("Invalid request payload", &w, http.StatusBadRequest)
		return
	}

	const genericErrorMessage = "Unable to renew certificate"
	signature, err := base64.StdEncoding.DecodeString(requestBody.Signature)
	if err != nil {
		log.Println("[-] Unable to parse signature: ", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Retrieve identity commitment based on the serial number
	serialNumber := requestBody.SerialNumber
	certData := h.repo.GetCertificateDataFromSerialNumber(serialNumber)
	committedIdentity := h.repo.GetCommitmentFromReservedSerialNumber(serialNumber)
	if committedIdentity == nil || certData == nil {
		log.Println("[-] Unable to retrieve identity commitment or certificate data for serial number: ", serialNumber)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Check if the certificate is revoked
	if certData.Revoked {
		log.Println("[-] Certificate is revoked for serial number: ", serialNumber)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}
	// Check if the certificate is still valid
	now := time.Now()
	if certData.ValidUntil.Time().Before(now) {
		log.Println("[-] Certificate has expired for serial number: ", serialNumber)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Verify signature
	// Expected message is "Revoke: <serial number>"
	message := []byte("Renew: " + serialNumber)
	signatureValid := h.repo.verifySignature(message, signature, committedIdentity.PublicKeyDER)
	if !signatureValid {
		log.Println("[-] Invalid signature for renewing serial number: ", serialNumber)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Update certificate data in DB
	newExpiryDate := certData.ValidUntil.Time().Add(time.Hour * 24 * 365) // Renew for one year
	if err := h.repo.RenewCertificate(serialNumber, newExpiryDate); err != nil {
		log.Println("[-] Failed to renew certificate: ", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
		return
	}

	// Generate new certificate
	serialAsBigInt, _ := new(big.Int).SetString(serialNumber, 10)
	validFrom := certData.ValidFrom.Time()
	certificate, err := h.repo.CreateCertificate(
		committedIdentity,
		h.repo.ValidatePublicKey(committedIdentity.PublicKeyDER),
		serialAsBigInt,
		&validFrom,
		&newExpiryDate,
	)
	if err != nil {
		fmt.Println("[-] Unable to renew certificate: ", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
		return
	}

	//Response
	response := map[string]string{
		"message":     "Certificate renewed successfully",
		"certificate": string(certificate),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *CertificateHandler) GetCertificateStatusHandler(w http.ResponseWriter, r *http.Request) {
	var request StatusRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handlers.ReturnErroredResponse("Invalid request format", &w, http.StatusBadRequest)
		return
	}

	const genericErrorMessage = "Unable to retrieve certificate status"

	// Validate nonce and timestamp for replay protection
	if err := h.nonceManager.ValidateAndUseNonce(request.Nonce, request.Timestamp); err != nil {
		log.Println("[-] Nonce validation failed: ", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Get certificate data
	serial := request.SerialNumber
	data := h.repo.GetStatusFromSerialNumber(serial)
	if data == nil {
		// Create unknown status response
		responseData := &StatusResponseData{
			SerialNumber: serial,
			CertStatus:   StatusUnknown,
			ThisUpdate:   time.Now(),
			Nonce:        request.Nonce,
		}

		signedResponse, err := h.responseSigner.SignStatusResponse(responseData)
		if err != nil {
			log.Println("[-] Failed to sign unknown status response:", err)
			handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(signedResponse)
		return
	}

	// Determine certificate status
	var certStatus string
	var revocationTime *time.Time

	if data.Revoked {
		certStatus = StatusRevoked
		revTime := data.RevocationDate.Time()
		revocationTime = &revTime
	} else {
		certStatus = StatusGood
	}

	// Create response data
	nextUpdate := time.Now() // Next update is immediate as it is in real time
	responseData := &StatusResponseData{
		SerialNumber:     serial,
		CertStatus:       certStatus,
		ThisUpdate:       time.Now(),
		NextUpdate:       &nextUpdate,
		RevocationTime:   revocationTime,
		RevocationReason: nil, // Could be extended to include reason codes
		Nonce:            request.Nonce,
	}

	// Sign the response
	signedResponse, err := h.responseSigner.SignStatusResponse(responseData)
	if err != nil {
		fmt.Printf("[-] Failed to sign status response: %v\n", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
		return
	}

	// Return signed response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(signedResponse)
}

func (h *CertificateHandler) GetRevocationListHandler(w http.ResponseWriter, r *http.Request) {
	var request CrlRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		handlers.ReturnErroredResponse("Invalid request format", &w, http.StatusBadRequest)
		return
	}

	if request.Page < 1 {
		handlers.ReturnErroredResponse("Invalid page parameter", &w, http.StatusBadRequest)
		return
	}

	if request.PageSize < 10 || request.PageSize > 100 {
		handlers.ReturnErroredResponse("Invalid page_size parameter, must be between 10 and 100", &w, http.StatusBadRequest)
		return
	}

	if request.Nonce < 1 {
		handlers.ReturnErroredResponse("Invalid nonce parameter", &w, http.StatusBadRequest)
		return
	}

	const genericErrorMessage = "Unable to retrieve revocation list"

	// Validate nonce and timestamp
	if err := h.nonceManager.ValidateAndUseNonce(request.Nonce, request.Timestamp); err != nil {
		log.Println("[-] Nonce validation failed:", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusBadRequest)
		return
	}

	// Get revoked certificates
	revokedCertificates, err := h.repo.GetRevokedCertificates(request.Page, request.PageSize)
	if err != nil {
		fmt.Println("[-] Failed to retrieve revocation list:", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
		return
	}

	totalCount := len(revokedCertificates)

	// Convert to response format
	revokedCertInfos := make([]RevokedCertInfo, len(revokedCertificates))
	for i, cert := range revokedCertificates {
		revokedCertInfos[i] = RevokedCertInfo{
			SerialNumber:   cert.SerialNumber,
			RevocationDate: cert.RevocationDate.Time(),
			// TODO: add RevocationReason
		}
	}

	// Create response data
	now := time.Now()
	nextUpdate := now // CRL is real-time, so next update is immediate

	responseData := &RevocationListData{
		RevokedCertificates: revokedCertInfos,
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
		Page:                request.Page,
		PageSize:            request.PageSize,
		TotalCount:          totalCount,
		Nonce:               request.Nonce,
	}

	// Sign the response
	signedResponse, err := h.responseSigner.SignRevocationListResponse(responseData)
	if err != nil {
		fmt.Printf("[-] Failed to sign revocation list response: %v\n", err)
		handlers.ReturnErroredResponse(genericErrorMessage, &w, http.StatusInternalServerError)
		return
	}

	// Return signed response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(signedResponse)
}
