package gossh

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
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
		HostKeyCallback: HostKeyCallback,
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
