package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"ca/internal/hsm"
)

type InfoHandler struct {
	hsm    *hsm.Hsm
	Router *http.ServeMux
}

type GetPublickKeyResponse struct {
	PublicKey string `json:"public_key"`
}

func BuildInfoHandler(hsm *hsm.Hsm) InfoHandler {
	router := http.NewServeMux()

	return InfoHandler{
		hsm:    hsm,
		Router: router,
	}
}

func (h *InfoHandler) RegisterRoutes() {
	h.Router.HandleFunc("/public", h.GetRootPublicKeyHandler)
}

func (h *InfoHandler) GetRootPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	publicKey := h.hsm.GetPublicKey(h.hsm.RootKeyId)

	w.Header().Set("Content-Type", "application/json")
	if publicKey == nil {
		fmt.Println("[-] Requested key is not in the HSM: ", h.hsm.RootKeyId)
		http.Error(w, "Unable to retrieve public key", http.StatusInternalServerError)
		return
	}

	publicKeyStr := base64.StdEncoding.EncodeToString(publicKey)
	fmt.Println(publicKeyStr)
	response, err := json.Marshal(GetPublickKeyResponse{
		PublicKey: publicKeyStr,
	})

	if err != nil {
		fmt.Println("[-] Unable to create response: ", err)
		http.Error(w, "Unable to retrieve public key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
