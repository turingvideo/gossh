package gossh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/turingvideo/gossh/teleport/lib/utils/socks"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	Logger   *zerolog.Logger
	Addr     string
	Username string
	Password string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer

	// LocalForwardPorts are the local ports listens on for port forwarding
	// (parameters to -L ssh flag).
	LocalForwardPorts []ForwardedPort

	// DynamicForwardedPorts are the list of ports listens on for dynamic
	// port forwarding (parameters to -D ssh flag).
	DynamicForwardedPorts []DynamicForwardedPort

	// Interactive, when set to true, launch a remote command
	// in interactive mode, i.e. attaching the temrinal to it
	Interactive bool
}

func (c *Client) SSH(ctx context.Context, command []string) error {
	sshConfig := &ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Password),
		},
		HostKeyCallback: HostKeyCallback,
	}

	client, err := ssh.Dial("tcp", c.Addr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to dial: %s", err)
	}
	defer client.Close()

	// If forwarding ports were specified, start port forwarding.
	c.startPortForwarding(ctx, client)

	// Issue "exec" request(s) to run on remote session.
	if len(command) > 0 {
		return c.runCommand(ctx, client, command)
	}

	// Issue "shell" request.
	return c.runShell(client)
}

func (c *Client) getLogger() *zerolog.Logger {
	if c.Logger == nil {
		c.Logger = &log.Logger
	}
	return c.Logger
}

// runShell starts an interactive SSH session/shell.
func (c *Client) runShell(client *ssh.Client) error {
	session, err := NewSession(client, c.Logger, c.Stdin, c.Stdout, c.Stderr)
	if err != nil {
		return err
	}
	if err = session.RunShell(nil); err != nil {
		return err
	}
	stderr := c.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	if session.ExitMsg == "" {
		fmt.Fprintf(stderr, "Connection to %v closed on %v.\n", c.Addr, time.Now().Format(time.ANSIC))
	} else {
		fmt.Fprintln(stderr, session.ExitMsg)
	}
	return nil
}

// runCommand executes a given bash command on an established NodeClient.
func (c *Client) runCommand(ctx context.Context, client *ssh.Client, command []string) error {
	session, err := NewSession(client, c.Logger, c.Stdin, c.Stdout, c.Stderr)
	if err != nil {
		return err
	}
	defer session.Close()
	if err := session.RunCommand(ctx, command, nil, c.Interactive); err != nil {
		return err
	}

	return nil
}

func (c *Client) startPortForwarding(ctx context.Context, client *ssh.Client) {
	if len(c.LocalForwardPorts) > 0 {
		for _, fp := range c.LocalForwardPorts {
			addr := net.JoinHostPort(fp.SrcIP, strconv.Itoa(fp.SrcPort))
			socket, err := net.Listen("tcp", addr)
			if err != nil {
				c.getLogger().Error().Msgf("Failed to bind to %v: %v.", addr, err)
				continue
			}
			go c.listenAndForward(ctx, client, socket, net.JoinHostPort(fp.DestHost, strconv.Itoa(fp.DestPort)))
		}
	}

	if len(c.DynamicForwardedPorts) > 0 {
		for _, fp := range c.DynamicForwardedPorts {
			addr := net.JoinHostPort(fp.SrcIP, strconv.Itoa(fp.SrcPort))
			socket, err := net.Listen("tcp", addr)
			if err != nil {
				c.getLogger().Error().Msgf("Failed to bind to %v: %v.", addr, err)
				continue
			}
			go c.dynamicListenAndForward(ctx, client, socket)
		}
	}
}

// listenAndForward listens on a given socket and forwards all incoming
// commands to the remote address through the SSH tunnel.
func (c *Client) listenAndForward(ctx context.Context, client *ssh.Client, listener net.Listener, remoteAddr string) {
	defer listener.Close()
	defer client.Close()

	for {
		// Accept connections from the client.
		conn, err := c.acceptWithContext(ctx, listener)
		if err != nil {
			c.getLogger().Error().Msgf("Port forwarding failed: %v.", err)
			break
		}

		// Proxy the connection to the remote address.
		go func() {
			err := c.proxyConnection(ctx, conn, remoteAddr, client)
			if err != nil {
				c.getLogger().Warn().Msgf("Failed to proxy connection: %v.", err)
			}
		}()
	}
}

// dynamicListenAndForward listens for connections, performs a SOCKS5
// handshake, and then proxies the connection to the requested address.
func (c *Client) dynamicListenAndForward(ctx context.Context, client *ssh.Client, listener net.Listener) {
	defer listener.Close()
	defer client.Close()

	for {
		// Accept connection from the client. Here the client is typically
		// something like a web browser or other SOCKS5 aware application.
		conn, err := listener.Accept()
		if err != nil {
			c.getLogger().Error().Msgf("Dynamic port forwarding (SOCKS5) failed: %v.", err)
			break
		}

		// Perform the SOCKS5 handshake with the client to find out the remote
		// address to proxy.
		remoteAddr, err := socks.Handshake(conn)
		if err != nil {
			c.getLogger().Error().Msgf("SOCKS5 handshake failed: %v.", err)
			break
		}
		c.getLogger().Debug().Msgf("SOCKS5 proxy forwarding requests to %v.", remoteAddr)

		// Proxy the connection to the remote address.
		go func() {
			err := c.proxyConnection(ctx, conn, remoteAddr, client)
			if err != nil {
				c.getLogger().Warn().Msgf("Failed to proxy connection: %v.", err)
			}
		}()
	}
}

// acceptWithContext calls "Accept" on the listener but will unblock when the
// context is canceled.
func (c *Client) acceptWithContext(ctx context.Context, l net.Listener) (net.Conn, error) {
	acceptCh := make(chan net.Conn, 1)
	errorCh := make(chan error, 1)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			errorCh <- err
			return
		}
		acceptCh <- conn
	}()

	select {
	case conn := <-acceptCh:
		return conn, nil
	case err := <-errorCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) proxyConnection(ctx context.Context, conn net.Conn, remoteAddr string, dialer *ssh.Client) error {
	defer conn.Close()
	defer c.getLogger().Debug().Msgf("Finished proxy from %v to %v.", conn.RemoteAddr(), remoteAddr)

	var (
		remoteConn net.Conn
		err        error
	)

	c.getLogger().Debug().Msgf("Attempting to connect proxy from %v to %v.", conn.RemoteAddr(), remoteAddr)
	for attempt := 1; attempt <= 5; attempt++ {
		remoteConn, err = dialer.Dial("tcp", remoteAddr)
		if err != nil {
			c.getLogger().Debug().Msgf("Proxy connection attempt %v: %v.", attempt, err)

			timer := time.NewTimer(time.Duration(100*attempt) * time.Millisecond)
			defer timer.Stop()

			// Wait and attempt to connect again, if the context has closed, exit
			// right away.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				continue
			}
		}
		// Connection established, break out of the loop.
		break
	}
	if err != nil {
		return fmt.Errorf("failed to connect to node: %v", remoteAddr)
	}
	defer remoteConn.Close()

	// Start proxying, close the connection if a problem occurs on either leg.
	errCh := make(chan error, 2)
	go func() {
		defer conn.Close()
		defer remoteConn.Close()

		_, err := io.Copy(conn, remoteConn)
		errCh <- err
	}()
	go func() {
		defer conn.Close()
		defer remoteConn.Close()

		_, err := io.Copy(remoteConn, conn)
		errCh <- err
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				c.getLogger().Warn().Msgf("Failed to proxy connection: %v.", err)
				errs = append(errs, err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return NewAggregate(errs...)
}
