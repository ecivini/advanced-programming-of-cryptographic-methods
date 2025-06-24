package handlers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"ca/internal/hsm"
)

// OCSP-like response status values
const (
	StatusGood    = 0
	StatusRevoked = 1
	StatusUnknown = 2
)

// Signed certificate status response structure
type SignedStatusResponse struct {
	// Response data (to be signed)
	ResponseData StatusResponseData `json:"response_data"`
	// Signature algorithm identifier
	SignatureAlgorithm string `json:"signature_algorithm"`
	// Base64 encoded signature
	Signature string `json:"signature"`
	// Response signing certificate chain (optional)
	SigningCert string `json:"signing_cert,omitempty"`
}

// The actual response data that gets signed
type StatusResponseData struct {
	// Certificate serial number being queried
	SerialNumber string `json:"serial_number"`
	// Certificate status (0=good, 1=revoked, 2=unknown)
	CertStatus int `json:"cert_status"`
	// Time when this response was generated
	ThisUpdate time.Time `json:"this_update"`
	// Time when next update will be available (optional)
	NextUpdate *time.Time `json:"next_update,omitempty"`
	// Revocation time (only if revoked)
	RevocationTime *time.Time `json:"revocation_time,omitempty"`
	// Revocation reason (only if revoked)
	RevocationReason *int `json:"revocation_reason,omitempty"`
	// Nonce from request (replay protection)
	Nonce string `json:"nonce"`
	// Responder ID
	ResponderID string `json:"responder_id"`
}

// Certificate status request with nonce for replay protection
type StatusRequest struct {
	SerialNumber string `json:"serial_number"`
	// Nonce for replay protection (base64 encoded)
	Nonce string `json:"nonce"`
	// Timestamp of request (additional replay protection)
	Timestamp time.Time `json:"timestamp"`
}

// Revocation list response with signature
type SignedRevocationListResponse struct {
	ResponseData       RevocationListData `json:"response_data"`
	SignatureAlgorithm string             `json:"signature_algorithm"`
	Signature          string             `json:"signature"`
	SigningCert        string             `json:"signing_cert,omitempty"`
}

type RevocationListData struct {
	// List of revoked certificates
	RevokedCertificates []RevokedCertInfo `json:"revoked_certificates"`
	// When this list was generated
	ThisUpdate time.Time `json:"this_update"`
	// When next update will be available
	NextUpdate time.Time `json:"next_update"`
	// Pagination info
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalCount int `json:"total_count"`
	// Nonce from request
	Nonce string `json:"nonce"`
	// Responder ID
	ResponderID string `json:"responder_id"`
}

type RevokedCertInfo struct {
	SerialNumber     string    `json:"serial_number"`
	RevocationDate   time.Time `json:"revocation_date"`
	RevocationReason *int      `json:"revocation_reason,omitempty"`
}

// Nonce manager for replay protection
type NonceManager struct {
	// In production, this should be a distributed cache (Redis, etc.)
	usedNonces map[string]time.Time
	// Maximum age for nonces (after this, they're removed from cache)
	maxAge time.Duration
}

func NewNonceManager() *NonceManager {
	return &NonceManager{
		usedNonces: make(map[string]time.Time),
		maxAge:     time.Minute * 10, // Nonces valid for 10 minutes
	}
}

// Validate nonce and mark as used
func (nm *NonceManager) ValidateAndUseNonce(nonce string, requestTime time.Time) error {
	// Clean up old nonces first
	nm.cleanup()

	// Check if nonce was already used
	if _, exists := nm.usedNonces[nonce]; exists {
		return fmt.Errorf("nonce already used (replay attack detected)")
	}

	// Check if request is too old
	if time.Since(requestTime) > nm.maxAge {
		return fmt.Errorf("request too old (timestamp: %v)", requestTime)
	}

	// Check if request is from the future (clock skew protection)
	if requestTime.After(time.Now().Add(time.Minute * 5)) {
		return fmt.Errorf("request from future (clock skew detected)")
	}

	// Mark nonce as used
	nm.usedNonces[nonce] = time.Now()
	return nil
}

// Clean up old nonces
func (nm *NonceManager) cleanup() {
	cutoff := time.Now().Add(-nm.maxAge)
	for nonce, timestamp := range nm.usedNonces {
		if timestamp.Before(cutoff) {
			delete(nm.usedNonces, nonce)
		}
	}
}

// Generate a cryptographically secure nonce
func GenerateNonce() (string, error) {
	nonce := make([]byte, 16) // 128-bit nonce
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}

// Response signer using HSM
type ResponseSigner struct {
	hsm         *hsm.Hsm
	responderID string
}

func NewResponseSigner(hsm *hsm.Hsm, responderID string) *ResponseSigner {
	return &ResponseSigner{
		hsm:         hsm,
		responderID: responderID,
	}
}

// Sign status response data
func (rs *ResponseSigner) SignStatusResponse(responseData *StatusResponseData) (*SignedStatusResponse, error) {
	// Set responder ID
	responseData.ResponderID = rs.responderID

	// Serialize response data for signing
	dataBytes, err := json.Marshal(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	// Create hash of the data
	hash := sha256.Sum256(dataBytes)

	// Sign the hash using HSM
	signer, err := rs.hsm.BuildECDSASigner(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	// Get signing certificate (optional - for certificate chain validation)
	signingCert, err := rs.getSigningCertificate()
	if err != nil {
		// Log error but don't fail - signing cert is optional
		fmt.Printf("Warning: failed to get signing certificate: %v\n", err)
		signingCert = ""
	}

	return &SignedStatusResponse{
		ResponseData:       *responseData,
		SignatureAlgorithm: "ECDSA-SHA256",
		Signature:          base64.StdEncoding.EncodeToString(signature),
		SigningCert:        signingCert,
	}, nil
}

// Sign revocation list response
func (rs *ResponseSigner) SignRevocationListResponse(responseData *RevocationListData) (*SignedRevocationListResponse, error) {
	// Set responder ID
	responseData.ResponderID = rs.responderID

	// Serialize response data for signing
	dataBytes, err := json.Marshal(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	// Create hash of the data
	hash := sha256.Sum256(dataBytes)

	// Sign the hash using HSM
	signer, err := rs.hsm.BuildECDSASigner(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to sign response: %w", err)
	}

	// Get signing certificate
	signingCert, err := rs.getSigningCertificate()
	if err != nil {
		fmt.Printf("Warning: failed to get signing certificate: %v\n", err)
		signingCert = ""
	}

	return &SignedRevocationListResponse{
		ResponseData:       *responseData,
		SignatureAlgorithm: "ECDSA-SHA256",
		Signature:          base64.StdEncoding.EncodeToString(signature),
		SigningCert:        signingCert,
	}, nil
}

// Get the signing certificate (CA certificate in this implementation)
func (rs *ResponseSigner) getSigningCertificate() (string, error) {
	// In a proper implementation, this might be a dedicated OCSP signing certificate
	// For now, we'll use the CA certificate
	caCertPEM, err := os.ReadFile("/certs/root.pem")
	if err != nil {
		return "", err
	}
	return string(caCertPEM), nil
}

// Response verifier for clients
type ResponseVerifier struct {
	caCert *x509.Certificate
}

func NewResponseVerifier(caCertPath string) (*ResponseVerifier, error) {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &ResponseVerifier{caCert: caCert}, nil
}

// Verify signed status response
func (rv *ResponseVerifier) VerifyStatusResponse(signedResponse *SignedStatusResponse) error {
	// Serialize response data
	dataBytes, err := json.Marshal(signedResponse.ResponseData)
	if err != nil {
		return fmt.Errorf("failed to marshal response data: %w", err)
	}

	// Create hash
	hash := sha256.Sum256(dataBytes)

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signedResponse.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature using CA public key
	// Note: In production, you might want to use a dedicated OCSP signing key
	switch signedResponse.SignatureAlgorithm {
	case "ECDSA-SHA256":
		return rv.verifyECDSASignature(hash[:], signature)
	default:
		return fmt.Errorf("unsupported signature algorithm: %s", signedResponse.SignatureAlgorithm)
	}
}

// Verify ECDSA signature
func (rv *ResponseVerifier) verifyECDSASignature(hash, signature []byte) error {
	// Parse ECDSA signature
	var ecdsaSig struct {
		R, S *big.Int
	}

	_, err := asn1.Unmarshal(signature, &ecdsaSig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
	}

	// Get ECDSA public key from CA certificate
	ecdsaPubKey, ok := rv.caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("CA certificate does not contain ECDSA public key")
	}

	// Verify signature
	if !ecdsa.Verify(ecdsaPubKey, hash, ecdsaSig.R, ecdsaSig.S) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
