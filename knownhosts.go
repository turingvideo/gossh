package gossh

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var errHostKeyVerifyFailed = errors.New("host key verification failed")

func GetKnownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

func GetKnownHostsHostKeyCallback() (ssh.HostKeyCallback, error) {
	file := GetKnownHostsFile()
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return knownhosts.New([]string{}...)
	}
	return knownhosts.New(file)
}

func appendKnownHostsHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	file := GetKnownHostsFile()
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	line := knownhosts.Line([]string{hostname, remote.String()}, key)
	_, err = f.WriteString(line)
	return err
}

func HostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	knownHostsHostKeyCallback, err := GetKnownHostsHostKeyCallback()
	if err != nil {
		return err
	}
	err = knownHostsHostKeyCallback(hostname, remote, key)

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return nil
	}

	if len(keyErr.Want) > 0 {
		fmt.Printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
		fmt.Printf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n")
		fmt.Printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
		fmt.Printf("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n")
		fmt.Printf("Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n")
		fmt.Printf("It is also possible that a host key has just been changed.\n")
		fmt.Printf("Please contact your system administrator.\n")
		fmt.Printf("Add correct host key in %s to get rid of this message.\n", GetKnownHostsFile())
		fmt.Printf("Offending ECDSA key in %s\n", GetKnownHostsFile())
		fmt.Printf("ECDSA host key for %s has changed and you have requested strict checking.\n",
			knownhosts.Normalize(hostname))
		return errHostKeyVerifyFailed
	} else if len(keyErr.Want) == 0 {
		// host key not found
		fmt.Printf("The authenticity of host '%s (%s)' can't be established.\n",
			knownhosts.Normalize(hostname),
			knownhosts.Normalize(remote.String()))

		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Printf("Are you sure you want to continue connecting (yes/no)? ")
			if !scanner.Scan() {
				break
			}
			text := scanner.Text()

			if strings.EqualFold(text, "no") {
				return errHostKeyVerifyFailed
			} else if strings.EqualFold(text, "yes") {
				return appendKnownHostsHostKey(hostname, remote, key)
			}
		}
	}
	return err
}
