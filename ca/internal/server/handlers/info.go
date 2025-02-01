package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"ca/internal/config"
	hsmSvc "ca/internal/hsm"
)

type GetPublickKeyResponse struct {
	PublicKey string `json:"public_key"`
}

func BuildInfoHandler(hsmCfg *config.HsmConfig) *http.ServeMux {
	router := http.NewServeMux()

	router.HandleFunc("/public", BuildGetRootPublicKeyHandler(hsmCfg))

	return router
}

func BuildGetRootPublicKeyHandler(hsmCfg *config.HsmConfig) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		hsm := hsmCfg.Hsm
		rootKeyId := hsmCfg.RootKeyId
		publicKey := hsmSvc.GetPublicKey(hsm, rootKeyId)

		w.Header().Set("Content-Type", "application/json")
		if publicKey == nil {
			fmt.Println("[-] Requested key is not in the HSM: ", rootKeyId)
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
	})
}
