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
	TYPE_STDOUT = 0
	TYPE_STDERR = 1
)

// Contains main authority information.
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

// connects to remote server using SSHConfig struct and returns *ssh.Session
func (ssh_conf *SSHConfig) connect() (*ssh.Session, error) {
	// auths holds the detected ssh auth methods
	auths := []ssh.AuthMethod{}

	// figure out what auths are requested, what is supported
	if ssh_conf.Password != "" {
		auths = append(auths, ssh.Password(ssh_conf.Password))
	}

	pubKey, err := getKeyFile(ssh_conf.Key)
	if err != nil {
		panic(err)
	}
	auths = append(auths, ssh.PublicKeys(pubKey))

	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		panic(err)
	}
	auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	defer sshAgent.Close()

	// Default port 22
	if ssh_conf.Port == "" {
		ssh_conf.Port = "22"
	}

	// Default current user
	if ssh_conf.User == "" {
		ssh_conf.User = os.Getenv("USER")
	}

	config := &ssh.ClientConfig{
		User:            ssh_conf.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// default maximum amount of time for the TCP connection to establish is 10s
	if ssh_conf.Timeout > 0 {
		config.Timeout = time.Duration(ssh_conf.Timeout) * time.Second
	} else {
		config.Timeout = time.Duration(10) * time.Second
	}

	client, err := ssh.Dial("tcp", ssh_conf.Server+":"+ssh_conf.Port, config)
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
func (ssh_conf *SSHConfig) Stream(command string, timeout int) (stdout chan string, stderr chan string, done chan bool, err error) {
	// connect to remote host
	session, err := ssh_conf.connect()
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

// Runs command on remote machine and returns its stdout as a string
func (ssh_conf *SSHConfig) Run(command string, timeout int) (outStr string, errStr string, isTimeout bool, err error) {
	stdoutChan, stderrChan, doneChan, err := ssh_conf.Stream(command, timeout)
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

func (ssh_conf *SSHConfig) RtRun(command string, lineHandler func(string string, lineType int), timeout int) (isTimeout bool, err error) {
	stdoutChan, stderrChan, doneChan, err := ssh_conf.Stream(command, timeout)
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
			lineHandler(outLine, TYPE_STDOUT)
		case errLine := <-stderrChan:
			lineHandler(errLine, TYPE_STDERR)
		}
	}
	// return the concatenation of all signals from the output channel
	return isTimeout, err
}

// Scp uploads localPath to remotePath like native scp console app.
// Warning: remotePath should contain the file name if the localPath is a regular file,
// however, if the localPath to copy is dir, the remotePath must be the dir into which the localPath will be copied.
func (ssh_conf *SSHConfig) Scp(localPath, remotePath string) error {
	if IsDir(localPath) {
		return ssh_conf.SCopyDir(localPath, remotePath, -1, true)
	}

	if IsRegular(localPath) {
		return ssh_conf.SCopyFile(localPath, remotePath)
	}

	panic("invalid local path: " + localPath)
}

// SCopyM copy multiple local file or dir to their corresponding remote path specified by para pathMappings.
func (ssh_conf *SSHConfig) ScpM(dirPathMappings map[string]string) error {
	return ssh_conf.SCopyM(dirPathMappings, -1, true)
}
