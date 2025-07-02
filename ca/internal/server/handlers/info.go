package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"ca/internal/hsm"
)

type InfoHandler struct {
	hsm *hsm.Hsm
}

// GetPublickKeyResponse represents the response structure for public key retrieval
// @Description Response containing the public key in PEM format
type GetPublickKeyResponse struct {
	PublicKey string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."`
}

func BuildInfoHandler(hsm *hsm.Hsm) InfoHandler {
	return InfoHandler{
		hsm: hsm,
	}
}

// GetRootPublicKeyHandler retrieves the root public key from the HSM
// @Summary Get root public key
// @Description Retrieves the public key of the Certificate Authority's root certificate from the Hardware Security Module (HSM)
// @Tags info
// @Accept json
// @Produce json
// @Success 200 {object} GetPublickKeyResponse "Successfully retrieved the root public key"
// @Failure 500 {object} map[string]string "Internal server error - unable to retrieve public key from HSM"
// @Router /info/root-public-key [get]
func (h *InfoHandler) GetRootPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	publicKey, err := h.hsm.GetPublicKeyPEM(h.hsm.RootKeyId)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		fmt.Println("[-] Requested key is not in the HSM: ", h.hsm.RootKeyId)
		http.Error(w, "Unable to retrieve public key", http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(GetPublickKeyResponse{
		PublicKey: publicKey,
	})

	if err != nil {
		fmt.Println("[-] Unable to create response: ", err)
		http.Error(w, "Unable to retrieve public key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
