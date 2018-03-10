package easyssh

import (
	"testing"
)

var sshConfig = &SSHConfig{
	User:     "SophisticaSean",
	Server:   "192.168.2.155",
	Password: "******",
	//Key:  "/.ssh/id_rsa",
	Port: "22",
}

func TestStream(t *testing.T) {
	t.Parallel()
	// input command/output string pairs
	testCases := [][]string{
		{`for i in $(seq 1 5); do echo "$i"; done`, "12345"},
		{`echo "test"`, "test"},
	}
	for _, testCase := range testCases {
		outChannel, errChannel, done, err := sshConfig.Stream(testCase[0], 10)
		if err != nil {
			t.Errorf("Stream failed: %s", err)
		}
		stillGoing := true
		stdout := ""
		stderr := ""
		for stillGoing {
			select {
			case <-done:
				stillGoing = false
			case line := <-outChannel:
				stdout += line
			case line := <-errChannel:
				stderr += line
			}
		}
		if stdout != testCase[1] {
			t.Errorf("Output didn't match expected: %s,%s", stdout, stderr)
		}
	}
}

func TestRun(t *testing.T) {
	t.Parallel()
	commands := []string{
		"echo test", `for i in $(ls); do echo "$i"; done`, "ls",
	}
	for _, cmd := range commands {
		stdout, stderr, istimeout, err := sshConfig.Run(cmd, 10)
		if err != nil {
			t.Errorf("Run failed: %s", err)
		}
		if stdout == "" {
			t.Errorf("Output was empty for command: %s,%s,%s,%v", cmd, stdout, stderr, istimeout)
		}
	}
}

//func TestSSHConfig_Scp(t *testing.T) {
//// Call Scp method with file you want to upload to remote server.
//err := sshConfig.Scp("/home/SophisticaSean/untitled1.html", "/tmp/target.html")

//// Handle errors
//if err != nil {
//panic("Can't run remote command: " + err.Error())
//} else {
//fmt.Println("success")

//}
//}
