package main

import (
	hsmSvc "ca/internal/hsm"
	"ca/internal/server"
)

func main() {
	// Create connection to the HSM
	hsm := hsmSvc.ConnectToHSM()

	server.InitServer(&hsm)
}
