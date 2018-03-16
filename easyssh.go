// Package easyssh provides a simple implementation of some SSH protocol
// features in Go. You can simply run a command on a remote server or get a file
// even simpler than native console SSH client. You don't need to think about
// Dials, sessions, defers, or public keys... Let easyssh think about it!
package easyssh

import (
	"bufio"
	"fmt"
	"io/ioutil"

	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// TypeSTDOUT is a constant representing stdout as 0
	TypeSTDOUT = 0
	// TypeSTDERR is a constant representing stdout as 1
	TypeSTDERR = 1
)

// SSHConfig contains main authority information.
// User field should be a name of user on remote server (ex. john in ssh john@example.com).
// Server field should be a remote machine address (ex. example.com in ssh john@example.com)
// Key is a path to private key on your local machine.
// Port is SSH server port on remote machine.
type SSHConfig struct {
	User     string
	Server   string
	Key      string
	Port     string
	Password string
	Timeout  int
}

// returns ssh.Signer from user you running app home path + cutted key path.
// (ex. pubkey,err := getKeyFile("/.ssh/id_rsa") )
func getKeyFile(keypath string) (ssh.Signer, error) {
	file := filepath.Join(keypath)
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	pubKey, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// Valid returns any errors with the given config if there are any
func (sshc *SSHConfig) Valid() error {
	// validate key path
	_, err := getKeyFile(sshc.Key)
	if err != nil {
		return err
	}

	// validate sshAgent
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return fmt.Errorf("could not connect to $SSH_AUTH_SOCK, is openssh installed? try `eval $(ssh-agent)`\n%v", err)
	}
	sshAgent.Close()

	if sshc.Server == "" {
		return fmt.Errorf("ssh config needs a Server IP or URL")
	}

	return nil
}

// connects to remote server using SSHConfig struct and returns *ssh.Session
func (sshc *SSHConfig) connect() (*ssh.Session, error) {
	// auths holds the detected ssh auth methods
	auths := []ssh.AuthMethod{}

	// figure out what auths are requested, what is supported
	if sshc.Password != "" {
		auths = append(auths, ssh.Password(sshc.Password))
	}

	pubKey, err := getKeyFile(sshc.Key)
	if err != nil {
		return err
	}
	auths = append(auths, ssh.PublicKeys(pubKey))

	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return fmt.Errorf("could not connect to $SSH_AUTH_SOCK, is openssh installed? try `eval $(ssh-agent)`\n%v", err)
	}
	auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	defer sshAgent.Close()

	// Default port 22
	if sshc.Port == "" {
		sshc.Port = "22"
	}

	// Default current user
	if sshc.User == "" {
		sshc.User = os.Getenv("USER")
	}

	config := &ssh.ClientConfig{
		User:            sshc.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// default maximum amount of time for the TCP connection to establish is 10s
	if sshc.Timeout > 0 {
		config.Timeout = time.Duration(sshc.Timeout) * time.Second
	} else {
		config.Timeout = time.Duration(10) * time.Second
	}

	client, err := ssh.Dial("tcp", sshc.Server+":"+sshc.Port, config)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

// Stream returns one channel that combines the stdout and stderr of the command
// as it is run on the remote machine, and another that sends true when the
// command is done. The sessions and channels will then be closed.
func (sshc *SSHConfig) Stream(command string, timeout int) (stdout chan string, stderr chan string, done chan bool, err error) {
	// connect to remote host
	session, err := sshc.connect()
	if err != nil {
		return stdout, stderr, done, err
	}

	// connect to both outputs (they are of type io.Reader)
	stdOutReader, err := session.StdoutPipe()
	if err != nil {
		return stdout, stderr, done, err
	}
	stderrReader, err := session.StderrPipe()
	if err != nil {
		return stdout, stderr, done, err
	}
	err = session.Start(command)
	stdoutScanner := bufio.NewScanner(stdOutReader)
	stderrScanner := bufio.NewScanner(stderrReader)
	// continuously send the command's output over the channel
	stdoutChan := make(chan string)
	stderrChan := make(chan string)
	done = make(chan bool)

	go func() {
		defer close(stdoutChan)
		defer close(stderrChan)
		defer close(done)

		go func() {
			for stdoutScanner.Scan() {
				stdoutChan <- stdoutScanner.Text()
			}
			for stderrScanner.Scan() {
				stderrChan <- stderrScanner.Text()
			}
			done <- true
		}()

		if -1 == timeout {
			// a long timeout simulate wait forever
			timeout = 24 * 3600
		}
		timeoutChan := time.After(time.Duration(timeout) * time.Second)
		select {
		case r := <-done:
			done <- r
		case <-timeoutChan:
			stderrChan <- fmt.Sprintf("Run command timeout: %s", command)
			done <- false
		}
	}()

	return stdoutChan, stderrChan, done, err
}

// Run runs command on remote machine and returns its stdout as a string
func (sshc *SSHConfig) Run(command string, timeout int) (outStr string, errStr string, isTimeout bool, err error) {
	stdoutChan, stderrChan, doneChan, err := sshc.Stream(command, timeout)
	if err != nil {
		return outStr, errStr, isTimeout, err
	}
	// read from the output channel until the done signal is passed
L:
	for {
		select {
		case done := <-doneChan:
			isTimeout = !done
			break L
		case outLine := <-stdoutChan:
			outStr += outLine + "\n"
		case errLine := <-stderrChan:
			errStr += errLine + "\n"
		}
	}
	// return the concatenation of all signals from the output channel
	return outStr, errStr, isTimeout, err
}

// RtRun runs a command on a remote machine but lets you define a lineHandler function to deal with incoming output and errors
func (sshc *SSHConfig) RtRun(command string, lineHandler func(string string, lineType int), timeout int) (isTimeout bool, err error) {
	stdoutChan, stderrChan, doneChan, err := sshc.Stream(command, timeout)
	if err != nil {
		return isTimeout, err
	}
	// read from the output channel until the done signal is passed
L:
	for {
		select {
		case done := <-doneChan:
			isTimeout = !done
			break L
		case outLine := <-stdoutChan:
			lineHandler(outLine, TypeSTDOUT)
		case errLine := <-stderrChan:
			lineHandler(errLine, TypeSTDERR)
		}
	}
	// return the concatenation of all signals from the output channel
	return isTimeout, err
}

// Scp uploads localPath to remotePath like native scp console app.
// Warning: remotePath should contain the file name if the localPath is a regular file,
// however, if the localPath to copy is dir, the remotePath must be the dir into which the localPath will be copied.
func (sshc *SSHConfig) Scp(localPath, remotePath string) error {
	if IsDir(localPath) {
		return sshc.SCopyDir(localPath, remotePath, -1, true)
	}

	if IsRegular(localPath) {
		return sshc.SCopyFile(localPath, remotePath)
	}

	return fmt.Errorf("invalid local path: %s", localPath)
}

// ScpM copy multiple local file or dir to their corresponding remote path specified by para pathMappings.
func (sshc *SSHConfig) ScpM(dirPathMappings map[string]string) error {
	return sshc.SCopyM(dirPathMappings, -1, true)
}
