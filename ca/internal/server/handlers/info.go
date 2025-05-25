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

type GetPublickKeyResponse struct {
	PublicKey string `json:"public_key"`
}

func BuildInfoHandler(hsm *hsm.Hsm) InfoHandler {
	return InfoHandler{
		hsm: hsm,
	}
}

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
