package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/rs/zerolog"
	"github.com/turingvideo/gossh"
	"golang.org/x/term"
	"gopkg.in/alecthomas/kingpin.v2"
)

type option struct {
	Debug                 bool
	UserHost              string
	Port                  int32
	RemoteCommand         []string
	LocalForwardPorts     []string
	DynamicForwardedPorts []string
	Options               []string
	Interactive           bool
	NoRemoteExec          bool
}

func main() {
	opt := option{}
	app := kingpin.New("gossh", "Another SSH client")

	app.Arg("[user@]host", "Remote hostname and the login to use").Required().StringVar(&opt.UserHost)
	app.Arg("command", "Command to execute on a remote host").StringsVar(&opt.RemoteCommand)
	app.Flag("port", "SSH port on a remote host").Short('p').Int32Var(&opt.Port)
	app.Flag("forward", "Forward localhost connections to remote server").Short('L').StringsVar(&opt.LocalForwardPorts)
	app.Flag("dynamic-forward", "Forward localhost connections to remote server using SOCKS5").Short('D').StringsVar(&opt.DynamicForwardedPorts)
	app.Flag("tty", "Allocate TTY").Short('t').BoolVar(&opt.Interactive)
	app.Flag("option", "OpenSSH options in the format used in the configuration file").Short('o').StringsVar(&opt.Options)
	app.Flag("no-remote-exec", "Don't execute remote command, useful for port forwarding").Short('N').BoolVar(&opt.NoRemoteExec)
	app.Flag("debug", "").Short('d').BoolVar(&opt.Debug)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	if opt.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		exitSignals := make(chan os.Signal, 1)
		signal.Notify(exitSignals, syscall.SIGTERM, syscall.SIGINT)

		<-exitSignals
		cancel()
	}()

	err := run(ctx, opt)
	if err != nil {
		utils.FatalError(err)
	}
}

func run(ctx context.Context, opt option) error {
	// split login & host
	var user, host string
	parts := strings.SplitN(opt.UserHost, "@", 2)
	if len(parts) > 1 {
		user = parts[0]
		host = parts[1]
	} else {
		user = ""
		host = opt.UserHost
	}

	portStr := "22"
	if opt.Port != 0 {
		portStr = strconv.Itoa(int(opt.Port))
	}
	addr := net.JoinHostPort(host, portStr)

	localForwardPorts, err := client.ParsePortForwardSpec(opt.LocalForwardPorts)
	if err != nil {
		return err
	}

	dynamicForwardedPorts, err := client.ParseDynamicPortForwardSpec(opt.DynamicForwardedPorts)
	if err != nil {
		return err
	}

	client := &gossh.Client{
		Addr:     addr,
		Username: user,
		PasswordCallback: func() (secret string, err error) {
			fmt.Print(user, "@", host, "'s password: ")
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return "", err
			}
			return string(bytePassword), nil
		},
		LocalForwardPorts:     localForwardPorts,
		DynamicForwardedPorts: dynamicForwardedPorts,
		Interactive:           opt.Interactive,
	}

	return client.SSH(ctx, nil)
}
