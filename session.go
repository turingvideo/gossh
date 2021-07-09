package gossh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/moby/term"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/turingvideo/gossh/teleport"
	"github.com/turingvideo/gossh/teleport/lib/defaults"
	"github.com/turingvideo/gossh/teleport/lib/sshutils"
	"github.com/turingvideo/gossh/teleport/lib/utils"
	"golang.org/x/crypto/ssh"
)

type Session struct {
	client *ssh.Client
	logger *zerolog.Logger

	// Standard input/outputs for this session
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// closer is used to simultaneously close all goroutines created by
	// this session. It's also used to wait for everyone to close
	closer *utils.CloseBroadcaster

	ExitMsg string
}

// ShellCreatedCallback can be supplied for every client. It will
// be called right after the remote shell is created, but the session
// hasn't begun yet.
//
// It allows clients to cancel SSH action
type ShellCreatedCallback func(s *ssh.Session, c *ssh.Client, terminal io.ReadWriteCloser) (exit bool, err error)

type interactiveCallback func(serverSession *ssh.Session, shell io.ReadWriteCloser) error

func NewSession(
	client *ssh.Client,
	logger *zerolog.Logger,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) (*Session, error) {
	if logger == nil {
		logger = &log.Logger
	}
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	session := &Session{
		client: client,
		logger: logger,
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		closer: utils.NewCloseBroadcaster(),
	}

	return session, nil
}

// runShell executes user's shell on the remote node under an interactive session
func (s *Session) RunShell(callback ShellCreatedCallback) error {
	return s.interactiveSession(func(sshSession *ssh.Session, shell io.ReadWriteCloser) error {
		// start the shell on the server:
		if err := sshSession.Shell(); err != nil {
			return err
		}
		// call the client-supplied callback
		if callback != nil {
			exit, err := callback(sshSession, s.client, shell)
			if exit {
				return err
			}
		}
		return nil
	})
}

func (s *Session) RunCommand(ctx context.Context, cmd []string, callback ShellCreatedCallback, interactive bool) error {
	// If stdin is not a terminal, refuse to allocate terminal on the server and
	// fallback to non-interactive mode
	if interactive && s.stdin == os.Stdin && !term.IsTerminal(os.Stdin.Fd()) {
		interactive = false
		fmt.Fprintf(os.Stderr, "TTY will not be allocated on the server because stdin is not a terminal\n")
	}

	// Start a interactive session ("exec" request with a TTY).
	//
	// Note that because a TTY was allocated, the terminal is in raw mode and any
	// keyboard based signals will be propogated to the TTY on the server which is
	// where all signal handling will occur.
	if interactive {
		return s.interactiveSession(func(sshSession *ssh.Session, term io.ReadWriteCloser) error {
			err := sshSession.Start(strings.Join(cmd, " "))
			if err != nil {
				return err
			}
			if callback != nil {
				exit, err := callback(sshSession, s.client, term)
				if exit {
					return err
				}
			}
			return nil
		})
	}

	// Start a non-interactive session ("exec" request without TTY).
	//
	// Note that for non-interactive sessions upon receipt of SIGINT the client
	// should send a SSH_MSG_DISCONNECT and shut itself down as gracefully as
	// possible. This is what the RFC recommends and what OpenSSH does:
	//
	//  * https://tools.ietf.org/html/rfc4253#section-11.1
	//  * https://github.com/openssh/openssh-portable/blob/05046d907c211cb9b4cd21b8eff9e7a46cd6c5ab/clientloop.c#L1195-L1444
	//
	// Unfortunately at the moment the Go SSH library Teleport uses does not
	// support sending SSH_MSG_DISCONNECT. Instead we close the SSH channel and
	// SSH client, and try and exit as gracefully as possible.
	return s.regularSession(func(sshSession *ssh.Session) error {
		var err error

		runContext, cancel := context.WithCancel(context.Background())
		go func() {
			defer cancel()
			err = sshSession.Run(strings.Join(cmd, " "))
		}()

		select {
		// Run returned a result, return that back to the caller.
		case <-runContext.Done():
			return err
		// The passed in context timed out. This is often due to the user hitting
		// Ctrl-C.
		case <-ctx.Done():
			err = s.Close()
			if err != nil {
				s.logger.Debug().Msgf("Unable to close SSH channel: %v", err)
			}
			err = s.client.Close()
			if err != nil {
				s.logger.Debug().Msgf("Unable to close SSH client: %v", err)
			}
			return ctx.Err()
		}
	})
}

func (s *Session) createSSHSession() (*ssh.Session, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}
	// pass language info into the remote session.
	evarsToPass := []string{"LANG", "LANGUAGE"}
	for _, evar := range evarsToPass {
		if value := os.Getenv(evar); value != "" {
			err = sess.Setenv(evar, value)
			if err != nil {
				s.logger.Warn().Err(err)
			}
		}
	}
	return sess, nil
}

// isTerminalAttached returns true when this session is be controlled by
// a real terminal.
// It will return False for sessions initiated by the Web client or
// for non-interactive sessions (commands)
func (s *Session) isTerminalAttached() bool {
	return s.stdin == os.Stdin && term.IsTerminal(os.Stdin.Fd())
}

func (s *Session) allocateTerminal(termType string, sshSession *ssh.Session) (io.ReadWriteCloser, error) {
	var err error

	// read the size of the terminal window:
	tsize := &term.Winsize{
		Width:  teleport.DefaultTerminalWidth,
		Height: teleport.DefaultTerminalHeight,
	}
	if s.isTerminalAttached() {
		tsize, err = term.GetWinsize(0)
		if err != nil {
			s.logger.Err(err)
		}
	}

	// ... and request a server-side terminal of the same size:
	err = sshSession.RequestPty(
		termType,
		int(tsize.Height),
		int(tsize.Width),
		ssh.TerminalModes{},
	)
	if err != nil {
		return nil, err
	}
	writer, err := sshSession.StdinPipe()
	if err != nil {
		return nil, err
	}
	reader, err := sshSession.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := sshSession.StderrPipe()
	if err != nil {
		return nil, err
	}

	if s.isTerminalAttached() {
		go s.updateTerminalSize(sshSession)
	}
	go func() {
		if _, err := io.Copy(os.Stderr, stderr); err != nil {
			s.logger.Debug().Msgf("Error reading remote STDERR: %v", err)
		}
	}()

	return utils.NewPipeNetConn(
		reader,
		writer,
		utils.MultiCloser(writer, sshSession, s.closer),
		&net.IPAddr{},
		&net.IPAddr{},
	), nil
}

func (s *Session) updateTerminalSize(sshSession *ssh.Session) {
	// SIGWINCH is sent to the process when the window size of the terminal has
	// changed.
	sigwinchCh := make(chan os.Signal, 1)
	signal.Notify(sigwinchCh, syscall.SIGWINCH)

	lastSize, err := term.GetWinsize(0)
	if err != nil {
		s.logger.Error().Msgf("Unable to get window size: %v", err)
		return
	}

	// Sync the local terminal with size received from the remote server every
	// two seconds. If we try and do it live, synchronization jitters occur.
	tickerCh := time.NewTicker(defaults.TerminalResizePeriod)
	defer tickerCh.Stop()

	for {
		select {
		// The client updated the size of the local PTY. This change needs to occur
		// on the server side PTY as well.
		case sigwinch := <-sigwinchCh:
			if sigwinch == nil {
				return
			}

			currSize, err := term.GetWinsize(0)
			if err != nil {
				s.logger.Warn().Msgf("Unable to get window size: %v.", err)
				continue
			}

			// Terminal size has not changed, don't do anything.
			if currSize.Height == lastSize.Height && currSize.Width == lastSize.Width {
				continue
			}

			// Send the "window-change" request over the channel.
			_, err = sshSession.SendRequest(
				sshutils.WindowChangeRequest,
				false,
				ssh.Marshal(sshutils.WinChangeReqParams{
					W: uint32(currSize.Width),
					H: uint32(currSize.Height),
				}))
			if err != nil {
				s.logger.Warn().Msgf("Unable to send %v reqest: %v.", sshutils.WindowChangeRequest, err)
				continue
			}

			s.logger.Debug().Msgf("Updated window size from %v to %v due to SIGWINCH.", lastSize, currSize)

			lastSize = currSize

		// Update size of local terminal with the last size received from remote server.
		case <-tickerCh.C:
			// Get the current size of the terminal and the last size report that was
			// received.
			currSize, err := term.GetWinsize(0)
			if err != nil {
				s.logger.Warn().Msgf("Unable to get current terminal size: %v.", err)
				continue
			}

			// Terminal size has not changed, don't do anything.
			if currSize.Width == lastSize.Width && currSize.Height == lastSize.Height {
				continue
			}

			// This changes the size of the local PTY. This will re-draw what's within
			// the window.
			err = term.SetWinsize(0, lastSize)
			if err != nil {
				s.logger.Warn().Msgf("Unable to update terminal size: %v.", err)
				continue
			}

			// This is what we use to resize the physical terminal window itself.
			os.Stdout.Write([]byte(fmt.Sprintf("\x1b[8;%d;%dt", lastSize.Height, lastSize.Width)))

			s.logger.Debug().Msgf("Updated window size from %v to %v due to remote window change.", currSize, lastSize)
		case <-s.closer.C:
			return
		}
	}
}

func (s *Session) regularSession(callback func(s *ssh.Session) error) error {
	session, err := s.createSSHSession()
	if err != nil {
		return err
	}
	session.Stdout = s.stdout
	session.Stderr = s.stderr
	session.Stdin = s.stdin
	return callback(session)
}

func (s *Session) interactiveSession(callback interactiveCallback) error {
	// determine what kind of a terminal we need
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = teleport.SafeTerminalType
	}

	// create the underlying session:
	sshSession, err := s.createSSHSession()
	if err != nil {
		return err
	}

	// allocate terminal on the server:
	remoteTerm, err := s.allocateTerminal(termType, sshSession)
	if err != nil {
		return err
	}
	defer remoteTerm.Close()

	// call the passed callback and give them the established
	// ssh session:
	if err := callback(sshSession, remoteTerm); err != nil {
		return err
	}

	// Catch term signals, but only if we're attached to a real terminal
	if s.isTerminalAttached() {
		s.watchSignals(remoteTerm)
	}

	// start piping input into the remote shell and pipe the output from
	// the remote shell into stdout:
	s.pipeInOut(remoteTerm)

	// switch the terminal to raw mode (and switch back on exit!)
	if s.isTerminalAttached() {
		ts, err := term.SetRawTerminal(0)
		if err != nil {
			s.logger.Warn().Err(err)
		} else {
			defer term.RestoreTerminal(0, ts)
		}
	}

	// wait for the session to end
	<-s.closer.C
	return nil
}

// watchSignals register UNIX signal handlers and properly terminates a remote shell session
// must be called as a goroutine right after a remote shell is created
func (s *Session) watchSignals(shell io.Writer) {
	exitSignals := make(chan os.Signal, 1)
	// catch SIGTERM
	signal.Notify(exitSignals, syscall.SIGTERM)
	go func() {
		defer s.closer.Close()
		<-exitSignals
	}()
	// Catch Ctrl-C signal
	ctrlCSignal := make(chan os.Signal, 1)
	signal.Notify(ctrlCSignal, syscall.SIGINT)
	go func() {
		for {
			<-ctrlCSignal
			_, err := shell.Write([]byte{3})
			if err != nil {
				s.logger.Error().Msgf(err.Error())
			}
		}
	}()
	// Catch Ctrl-Z signal
	ctrlZSignal := make(chan os.Signal, 1)
	signal.Notify(ctrlZSignal, syscall.SIGTSTP)
	go func() {
		for {
			<-ctrlZSignal
			_, err := shell.Write([]byte{26})
			if err != nil {
				s.logger.Error().Msgf(err.Error())
			}
		}
	}()
}

// pipeInOut launches two goroutines: one to pipe the local input into the remote shell,
// and another to pipe the output of the remote shell into the local output
func (s *Session) pipeInOut(shell io.ReadWriteCloser) {
	// copy from the remote shell to the local output
	go func() {
		defer s.closer.Close()
		_, err := io.Copy(s.stdout, shell)
		if err != nil {
			s.logger.Error().Msgf(err.Error())
		}
	}()

	// copy from the local input to the remote shell:
	go func() {
		defer s.closer.Close()
		buf := make([]byte, 128)

		stdin := s.stdin
		for {
			n, err := stdin.Read(buf)
			if err != nil {
				fmt.Fprintf(s.stderr, "\r\n%v\r\n", err)
				return
			}

			if n > 0 {
				_, err = shell.Write(buf[:n])
				if err != nil {
					s.ExitMsg = err.Error()
					return
				}
			}
		}
	}()
}

func (s *Session) Close() error {
	if s.closer != nil {
		s.closer.Close()
	}
	return nil
}
