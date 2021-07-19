package gossh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/turingvideo/gossh/teleport/lib/client"
	"github.com/turingvideo/gossh/teleport/lib/sshutils/scp"
	"github.com/turingvideo/gossh/teleport/lib/utils"
	"github.com/turingvideo/gossh/teleport/lib/utils/socks"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	Logger           *zerolog.Logger
	Addr             string
	Username         string
	Password         string
	PasswordCallback func() (secret string, err error)
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer

	// ExitStatus carries the returned value (exit status) of the remote
	// process execution (via SSH exec)
	ExitStatus int

	// LocalForwardPorts are the local ports listens on for port forwarding
	// (parameters to -L ssh flag).
	LocalForwardPorts client.ForwardedPorts

	// DynamicForwardedPorts are the list of ports listens on for dynamic
	// port forwarding (parameters to -D ssh flag).
	DynamicForwardedPorts client.DynamicForwardedPorts

	// Interactive, when set to true, launch a remote command
	// in interactive mode, i.e. attaching the temrinal to it
	Interactive bool

	// NoRemoteExec will not execute a remote command after connecting to a host,
	// will block instead. Useful when port forwarding. Equivalent of -N for OpenSSH.
	NoRemoteExec bool

	// OnShellCreated gets called when the shell is created. It's
	// safe to keep it nil.
	OnShellCreated ShellCreatedCallback
}

type scpConfig struct {
	cmd       scp.Command
	addr      string
	hostLogin string
}

func (c *Client) SSH(ctx context.Context, command []string) error {
	client, err := c.connect()
	if err != nil {
		return err
	}
	defer client.Close()

	// If forwarding ports were specified, start port forwarding.
	c.startPortForwarding(ctx, client)

	// If no remote command execution was requested, block on the context which
	// will unblock upon error or SIGINT.
	if c.NoRemoteExec {
		c.getLogger().Debug().Msgf("Connected to node, no remote command execution was requested, blocking until context closes.")
		<-ctx.Done()

		// Only return an error if the context was canceled by something other than SIGINT.
		if ctx.Err() != context.Canceled {
			return ctx.Err()
		}
		return nil
	}

	// Issue "exec" request(s) to run on remote session.
	if len(command) > 0 {
		return c.runCommand(ctx, client, command)
	}

	// Issue "shell" request.
	return c.runShell(client)
}

// SCP securely copies file(s) from one SSH server to another
func (c *Client) SCP(ctx context.Context, args []string, port int, flags scp.Flags, quiet bool) (err error) {
	if len(args) < 2 {
		return trace.Errorf("need at least two arguments for scp")
	}
	first := args[0]
	last := args[len(args)-1]

	// local copy?
	if !isRemoteDest(first) && !isRemoteDest(last) {
		return trace.BadParameter("making local copies is not supported")
	}

	var progressWriter io.Writer
	if !quiet {
		progressWriter = c.Stdout
		if progressWriter == nil {
			progressWriter = os.Stdout
		}
	}

	// gets called to convert SSH error code to tc.ExitStatus
	onError := func(err error) error {
		exitError, _ := trace.Unwrap(err).(*ssh.ExitError)
		if exitError != nil {
			c.ExitStatus = exitError.ExitStatus()
		}
		return err
	}

	tpl := scp.Config{
		User:           c.Username,
		ProgressWriter: progressWriter,
		Flags:          flags,
	}

	var config *scpConfig
	// upload:
	if isRemoteDest(last) {
		config, err = uploadConfig(ctx, tpl, port, args)
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		config, err = downloadConfig(ctx, tpl, port, args)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	client, err := c.connect()
	if err != nil {
		return err
	}
	defer client.Close()

	return onError(c.executeSCP(ctx, client, config.cmd))
}

func (c *Client) connect() (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	if c.Password != "" {
		auth = append(auth, ssh.Password(c.Password))
	}
	if c.PasswordCallback != nil {
		auth = append(auth, ssh.PasswordCallback(c.PasswordCallback))
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            auth,
		HostKeyCallback: HostKeyCallback,
	}

	client, err := ssh.Dial("tcp", c.Addr, sshConfig)
	if err != nil {
		c.ExitStatus = 1
		return nil, fmt.Errorf("failed to dial: %s", err)
	}
	return client, nil
}

// ExecuteSCP runs remote scp command(shellCmd) on the remote server and
// runs local scp handler using SCP Command
func (c *Client) executeSCP(ctx context.Context, client *ssh.Client, cmd scp.Command) error {
	shellCmd, err := cmd.GetRemoteShellCmd()
	if err != nil {
		return err
	}

	s, err := client.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()

	stdin, err := s.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := s.StdoutPipe()
	if err != nil {
		return err
	}

	// Stream scp's stderr so tsh gets the verbose remote error
	// if the command fails
	stderr, err := s.StderrPipe()
	if err != nil {
		return err
	}
	//nolint:errcheck
	go io.Copy(os.Stderr, stderr)

	ch := utils.NewPipeNetConn(
		stdout,
		stdin,
		utils.MultiCloser(),
		&net.IPAddr{},
		&net.IPAddr{},
	)

	execC := make(chan error, 1)
	go func() {
		err := cmd.Execute(ch)
		if err != nil && !trace.IsEOF(err) {
			c.getLogger().Warn().Err(err).Msg("Failed to execute SCP command.")
		}
		stdin.Close()
		execC <- err
	}()

	runC := make(chan error, 1)
	go func() {
		err := s.Run(shellCmd)
		if err != nil && errors.Is(err, &ssh.ExitMissingError{}) {
			// TODO(dmitri): currently, if the session is aborted with (*session).Close,
			// the remote side cannot send exit-status and this error results.
			// To abort the session properly, Teleport needs to support `signal` request
			err = nil
		}
		runC <- err
	}()

	var runErr error
	select {
	case <-ctx.Done():
		if err := s.Close(); err != nil {
			c.getLogger().Debug().Err(err).Msg("Failed to close the SSH session.")
		}
		err, runErr = <-execC, <-runC
	case err = <-execC:
		runErr = <-runC
	case runErr = <-runC:
		err = <-execC
	}

	if runErr != nil && (err == nil || trace.IsEOF(err)) {
		err = runErr
	}
	if trace.IsEOF(err) {
		err = nil
	}
	return err
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
	if err = session.RunShell(c.OnShellCreated); err != nil {
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
	if err := session.RunCommand(ctx, command, c.OnShellCreated, c.Interactive); err != nil {
		originErr := trace.Unwrap(err)
		exitErr, ok := originErr.(*ssh.ExitError)
		if ok {
			c.ExitStatus = exitErr.ExitStatus()
		} else {
			// if an error occurs, but no exit status is passed back, GoSSH returns
			// a generic error like this. in this case the error message is printed
			// to stderr by the remote process so we have to quietly return 1:
			if strings.Contains(originErr.Error(), "exited without exit status") {
				c.ExitStatus = 1
			}
		}

		return trace.Wrap(err)
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

func isRemoteDest(name string) bool {
	return strings.ContainsRune(name, ':')
}

func getSCPDestination(target string, port int) (dest *scp.Destination, addr string, err error) {
	dest, err = scp.ParseSCPDestination(target)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	addr = net.JoinHostPort(dest.Host.Host(), strconv.Itoa(port))
	return dest, addr, nil
}

func uploadConfig(ctx context.Context, tpl scp.Config, port int, args []string) (config *scpConfig, err error) {
	// args are guaranteed to have len(args) > 1
	filesToUpload := args[:len(args)-1]
	// copy everything except the last arg (the destination)
	destPath := args[len(args)-1]

	// If more than a single file were provided, scp must be in directory mode
	// and the target on the remote host needs to be a directory.
	var directoryMode bool
	if len(filesToUpload) > 1 {
		directoryMode = true
	}

	dest, addr, err := getSCPDestination(destPath, port)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tpl.RemoteLocation = dest.Path
	tpl.Flags.Target = filesToUpload
	tpl.Flags.DirectoryMode = directoryMode

	cmd, err := scp.CreateUploadCommand(tpl)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &scpConfig{
		cmd:       cmd,
		addr:      addr,
		hostLogin: dest.Login,
	}, nil
}

func downloadConfig(ctx context.Context, tpl scp.Config, port int, args []string) (config *scpConfig, err error) {
	// args are guaranteed to have len(args) > 1
	src, addr, err := getSCPDestination(args[0], port)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tpl.RemoteLocation = src.Path
	tpl.Flags.Target = args[1:]

	cmd, err := scp.CreateDownloadCommand(tpl)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &scpConfig{
		cmd:       cmd,
		addr:      addr,
		hostLogin: src.Login,
	}, nil
}
