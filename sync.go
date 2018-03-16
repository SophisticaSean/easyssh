package easyssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// SCopy copy localDirPath to the remote dir specified by remoteDirPath,
// Be aware that localDirPath and remoteDirPath should exists before SCopy.
// At last, you should know, timeout is not reliable.
func (ssh_conf *SSHConfig) SCopyDir(localDirPath, remoteDirPath string, timeout int, verbose bool) error {
	localDirPath = RemoveTrailingSlash(localDirPath)
	remoteDirPath = RemoveTrailingSlash(remoteDirPath)

	if !IsFileExists(localDirPath) {
		return errors.New("no such dir: " + localDirPath)
	}

	localDirParentPath := filepath.Dir(localDirPath)
	localDirname := filepath.Base(localDirPath)
	tgzName := fmt.Sprintf("%s_%s.tar.gz", Sha1(fmt.Sprintf("%s_%d", localDirPath, time.Now().UnixNano())), localDirname)
	defer Local("cd %s;rm -f %s", localDirParentPath, tgzName)
	defer ssh_conf.Run(fmt.Sprintf("cd %s;rm -f %s", remoteDirPath, tgzName), timeout)

	_, err := Local("cd %s;tar czf %s %s", localDirParentPath, tgzName, localDirname)
	if err != nil {
		return errors.New(fmt.Sprintf("create tgz pack for (%s) error: %s", localDirPath, err.Error()))
	}

	copyM := fmt.Sprintf("%s -> %s", localDirPath, remoteDirPath)
	tgzPath := filepath.Join(localDirParentPath, tgzName)
	if err = ssh_conf.SCopyFile(tgzPath, filepath.Join(remoteDirPath, tgzName)); err != nil {
		if verbose {
			fmt.Printf("upload %s error\n", copyM)
		}
		return err
	}

	isTimeout, err := ssh_conf.RtRun(fmt.Sprintf("cd %s;tar xf %s", remoteDirPath, tgzName), func(line string, lineType int) {
		if verbose && TypeSTDERR == lineType {
			fmt.Println(line)
		}
	}, timeout)

	if err != nil {
		return errors.New("extract tgz error: " + err.Error())
	}

	if isTimeout {
		return errors.New(fmt.Sprintf("SCopy timeout error: %s", copyM))
	}

	return nil
}

// CopyFile uploads srcFilePath to remote machine like native scp console app.
// destFilePath should be an absolute file path including filename and cannot be a dir.
func (ssh_conf *SSHConfig) SCopyFile(srcFilePath, destFilePath string) error {
	return ssh_conf.Work(func(session *ssh.Session) error {
		src, err := os.Open(srcFilePath)
		if err != nil {
			return err
		}

		stat, err := src.Stat()
		if err != nil {
			return err
		}

		go func() {
			stdin, _ := session.StdinPipe()
			fmt.Fprintf(stdin, "C%#o %d %s\n", stat.Mode().Perm(), stat.Size(), filepath.Base(destFilePath))
			if stat.Size() > 0 {
				io.Copy(stdin, src)
			}
			fmt.Fprint(stdin, "\x00")
			stdin.Close()
			src.Close()
		}()

		return session.Run(fmt.Sprintf("scp -t %s", destFilePath))
	})
}

// SCopyM copy multiple local path to their corresponding remote path specified by para pathMappings.
// Warning: to copy a local file, the remote path should contains the filename, however, to copy
// a local dir, the remote path must be a dir into which the local path will be copied.
func (ssh_conf *SSHConfig) SCopyM(pathMappings map[string]string, timeout int, verbose bool) error {
	errCh := make(chan error, len(pathMappings))
	doneCh := make(chan bool, len(pathMappings))
	var err error
	for localPath, remotePath := range pathMappings {
		go func(local, remote string) {
			if err == nil {
				if err = ssh_conf.Scp(local, remote); err != nil {
					errCh <- err
				} else {
					doneCh <- true
				}
			}
		}(localPath, remotePath)
	}

	if -1 == timeout {
		// a long timeout simulate wait forever
		timeout = 24 * 3600
	}
	timeoutChan := time.After(time.Duration(timeout) * time.Second)
L:
	for i := 0; i < len(pathMappings); i++ {
		select {
		case <-doneCh:
		case err = <-errCh:
			break L
		case <-timeoutChan:
			err = errors.New("SCopyM timeout error")
			break L
		}
	}
	return err
}

func (ssh_conf *SSHConfig) Work(fn func(session *ssh.Session) error) error {
	session, err := ssh_conf.connect()
	if err != nil {
		return err
	}
	defer session.Close()
	return fn(session)
}

// SafeScp first copy localPath to remote /tmp path, then move tmp file to remotePath if upload successfully.
func (ssh_conf *SSHConfig) SafeScp(localPath, remotePath string) error {
	if IsDir(localPath) {
		return ssh_conf.SCopyDir(localPath, remotePath, -1, false)
	}

	remoteTmpName := Sha1(fmt.Sprintf("%s_%d", localPath, time.Now().UnixNano()))
	destTmpPath := filepath.Join("/tmp", remoteTmpName)
	err := ssh_conf.SCopyFile(localPath, destTmpPath)
	defer ssh_conf.Run(fmt.Sprintf("cd /tmp;rm -f %s", remoteTmpName), -1)

	if err != nil {
		return err
	}
	_, _, _, err = ssh_conf.Run(fmt.Sprintf("mv %s %s", destTmpPath, remotePath), -1)
	return err
}
