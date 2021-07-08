package gossh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHClient struct {
}

type Config struct {
	Logger      *zerolog.Logger
	Addr        string
	Username    string
	Password    string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Interactive bool
}

var errHostKeyVerifyFailed = errors.New("host key verification failed")

func NewClient() (c *SSHClient, err error) {
	c = &SSHClient{}
	return
}

func SSH(ctx context.Context, cfg *Config, command []string) error {
	sshConfig := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(cfg.Password),
		},
		// HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", cfg.Addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to dial: %s", err)
	}
	defer client.Close()

	// Issue "exec" request(s) to run on remote session.
	if len(command) > 0 {
		return runCommand(ctx, client, cfg, command)
	}

	// Issue "shell" request.
	return runShell(client, cfg)
}

// runShell starts an interactive SSH session/shell.
func runShell(client *ssh.Client, cfg *Config) error {
	session, err := NewSession(client, cfg.Logger, cfg.Stdin, cfg.Stdout, cfg.Stderr)
	if err != nil {
		return err
	}
	if err = session.RunShell(nil); err != nil {
		return err
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	if session.ExitMsg == "" {
		fmt.Fprintf(stderr, "Connection to %v closed on %v.\n", cfg.Addr, time.Now().Format(time.ANSIC))
	} else {
		fmt.Fprintln(stderr, session.ExitMsg)
	}
	return nil
}

// runCommand executes a given bash command on an established NodeClient.
func runCommand(ctx context.Context, client *ssh.Client, cfg *Config, command []string) error {
	session, err := NewSession(client, cfg.Logger, cfg.Stdin, cfg.Stdout, cfg.Stderr)
	if err != nil {
		return err
	}
	defer session.Close()
	if err := session.RunCommand(ctx, command, nil, cfg.Interactive); err != nil {
		return err
	}

	return nil
}

func getKnownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

func getKnownHostsHostKeyCallback() (ssh.HostKeyCallback, error) {
	file := getKnownHostsFile()
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return knownhosts.New([]string{}...)
	}
	return knownhosts.New(file)
}

func appendKnownHostsHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	file := getKnownHostsFile()
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	line := knownhosts.Line([]string{hostname, remote.String()}, key)
	_, err = f.WriteString(line)
	return err
}

func hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	knownHostsHostKeyCallback, err := getKnownHostsHostKeyCallback()
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
		fmt.Printf("Add correct host key in %s to get rid of this message.\n", getKnownHostsFile())
		fmt.Printf("Offending ECDSA key in %s\n", getKnownHostsFile())
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
