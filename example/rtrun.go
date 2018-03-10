package main

import (
	"fmt"

	"github.com/SophisticaSean/easyssh"
)

func main() {
	// Create SSHConfig instance with remote username, server address and path to private key.
	ssh := &easyssh.SSHConfig{
		User:   "SophisticaSean",
		Server: "192.168.2.155",
		// Optional key or Password without either we try to contact your agent SOCKET
		// Password: "******",
	}

	// Call Run method with command you want to run on remote server.
	ssh.RtRun("ps aufx", func(stdoutLine string, lineType int) {
		fmt.Println(stdoutLine)
	}, 60)

}
