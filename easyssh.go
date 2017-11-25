// Package easyssh provides a simple implementation of some SSH protocol
// features in Go. You can simply run a command on a remote server or get a file
// even simpler than native console SSH client. You don't need to think about
// Dials, sessions, defers, or public keys... Let easyssh think about it!
package easyssh

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Contains main authority information.
// User field should be a name of user on remote server (ex. john in ssh john@example.com).
// Server field should be a remote machine address (ex. example.com in ssh john@example.com)
// Key is a path to private key on your local machine.
// Port is SSH server port on remote machine.
// Note: easyssh looking for private key in user's home directory (ex. /home/john + Key).
// Then ensure your Key begins from '/' (ex. /.ssh/id_rsa)
type SSHConfig struct {
	User     string
	Server   string
	Key      string
	Port     string
	Password string
}

// returns ssh.Signer from user you running app home path + cutted key path.
// (ex. pubkey,err := getKeyFile("/.ssh/id_rsa") )
func getKeyFile(keypath string) (ssh.Signer, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	file := filepath.Join(usr.HomeDir, keypath)
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

	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		defer sshAgent.Close()
	}

	if pubKey, err := getKeyFile(ssh_conf.Key); err == nil {
		auths = append(auths, ssh.PublicKeys(pubKey))
	}

	config := &ssh.ClientConfig{
		User: ssh_conf.User,
		Auth: auths,
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
	outReader, err := session.StdoutPipe()
	if err != nil {
		return stdout, stderr, done, err
	}
	errReader, err := session.StderrPipe()
	if err != nil {
		return stdout, stderr, done, err
	}
	// combine outputs, create a line-by-line scanner
	stdoutReader := io.MultiReader(outReader)
	stderrReader := io.MultiReader(errReader)
	err = session.Start(command)
	stdoutScanner := bufio.NewScanner(stdoutReader)
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
		case done:= <-doneChan:
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

func (ssh_conf *SSHConfig) RtRun(command string, stdLineHandler, errLineHandler func(string), timeout int) (isTimeout bool, err error) {
	stdoutChan, stderrChan, doneChan, err := ssh_conf.Stream(command, timeout)
	if err != nil {
		return isTimeout, err
	}
	// read from the output channel until the done signal is passed
L:
	for {
		select {
		case isTimeout = <-doneChan:
			break L
		case outLine := <-stdoutChan:
			stdLineHandler(outLine)
		case errLine := <-stderrChan:
			errLineHandler(errLine)
		}
	}
	// return the concatenation of all signals from the output channel
	return isTimeout, err
}

// Scp uploads sourceFile to remote machine like native scp console app.
// targetPath should be an absolute file path including filename and cannot be a dir.
func (ssh_conf *SSHConfig) Scp(srcFilePath string, destFilePath string) error {
	session, err := ssh_conf.connect()

	if err != nil {
		return err
	}
	defer session.Close()

	src, err := os.Open(srcFilePath)
	if err != nil {
		return err
	}
	defer src.Close()

	stat, err := src.Stat()
	if err != nil {
		return err
	}

	go func() {
		w, _ := session.StdinPipe()
		fmt.Fprintln(w, "C0644", stat.Size(), filepath.Base(destFilePath))
		if stat.Size() > 0 {
			io.Copy(w, src)
		}
		fmt.Fprint(w, "\x00")
		w.Close()
	}()

	return session.Run(fmt.Sprintf("scp -tr %s", destFilePath))
}
