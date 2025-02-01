package main

import (
	"ca/internal/config"
	hsmSvc "ca/internal/hsm"
	"ca/internal/server"
	"fmt"
)

func main() {
	// Create connection to the HSM
	hsm := hsmSvc.ConnectToHSM()
	rootKeyId := hsmSvc.GetRootKeyId(hsm)

	// TODO: Handle root certificate creation
	if rootKeyId == nil {
		rootKeyId = hsmSvc.CreateRootKey(hsm)
	}
	fmt.Println("[+] Root key id: ", *rootKeyId)

	// Start server
	hsmCfg := config.HsmConfig{
		Hsm:       hsm,
		RootKeyId: *rootKeyId,
	}

	server.InitServer(hsmCfg)
}
