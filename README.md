# easyssh

# Forked for Go 1.10+ support

## Description

Package easyssh provides a simple implementation of some SSH protocol features in Go.
You can simply run command on remote server or upload a file even simple than native console SSH client.
Do not need to think about Dials, sessions, defers and public keys...Let easyssh will be think about it!

## Scp

Scp support single file or a directory.

```go
sshconfig := &easyssh.SSHConfig{...}
sshconfig.Scp(localpath, remotepath)
```

ScpM support copy multiple files to multiple destination on remote simultaneously.

```go
sshconfig := &easyssh.SSHConfig{...}
sshconfig.ScpM(pathmapping)
```

## Install

```
go get github.com/SophisticaSean/easyssh
```

## So easy to use

[Run a command on remote server and get STDOUT output](https://github.com/SophisticaSean/easyssh/blob/master/example/run.go)

[Run a command on remote server and get STDOUT output line by line](https://github.com/SophisticaSean/easyssh/blob/master/example/rtrun.go)

[Upload a file to remote server](https://github.com/SophisticaSean/easyssh/blob/master/example/scp.go)

[Upload a directory to remote server](https://github.com/SophisticaSean/easyssh/blob/master/example/scopy.go)
