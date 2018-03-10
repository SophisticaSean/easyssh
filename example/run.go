package main

import (
	"github.com/SophisticaSean/easyssh"
)

func main() {
	// Create SSHConfig instance with remote username, server address and path to private key.
	ssh := &easyssh.SSHConfig{
		User:   "john",
		Server: "example.com",
		// Optional key or Password without either we try to contact your agent SOCKET
		//Password: "password",
		Key:  "/.ssh/id_rsa",
		Port: "22",
	}

	// Call Run method with command you want to run on remote server.
	_, _, _, err := ssh.Run("ps aufx", 10)
	// Handle errors
	if err != nil {
		panic("Can't run remote command: " + err.Error())
	}

}
