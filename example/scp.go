package main

import (
	"fmt"
	"github.com/SophisticaSean/easyssh"
)

func main() {
	// Create SSHConfig instance with remote username, server address and path to private key.
	ssh := &easyssh.SSHConfig{
		User:     "root",
		Server:   "example.com",
		Password: "******",
		Port:     "22",
	}

	// Call Scp method with file you want to upload to remote server.
	err := ssh.Scp("/root/source.csv", "/tmp/target.csv")

	// Handle errors
	if err != nil {
		panic("Can't run remote command: " + err.Error())
	} else {
		fmt.Println("success")

	}
}
