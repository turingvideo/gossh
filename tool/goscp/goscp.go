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

	"github.com/rs/zerolog"
	"github.com/turingvideo/gossh"
	"github.com/turingvideo/gossh/teleport/lib/sshutils/scp"
	"github.com/turingvideo/gossh/teleport/lib/utils"
	"golang.org/x/term"
	"gopkg.in/alecthomas/kingpin.v2"
)

type option struct {
	// Src:dest parameter for SCP
	CopySpec      []string
	Port          int32
	RecursiveCopy bool
	PreserveAttrs bool
	Quiet         bool
	Debug         bool
}

func main() {
	opt := option{}
	app := kingpin.New("goscp", "Another SCP client")

	app.Arg("from, to", "Source and destination to copy").Required().StringsVar(&opt.CopySpec)
	app.Flag("recursive", "Recursive copy of subdirectories").Short('r').BoolVar(&opt.RecursiveCopy)
	app.Flag("port", "Port to connect to on the remote host").Short('P').Int32Var(&opt.Port)
	app.Flag("preserve", "Preserves access and modification times from the original file").Short('p').BoolVar(&opt.PreserveAttrs)
	app.Flag("quiet", "Quiet mode").Short('q').BoolVar(&opt.Quiet)
	app.Flag("debug", "").Short('d').BoolVar(&opt.Debug)

	kingpin.MustParse(app.Parse(os.Args[1:]))

	if opt.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		exitSignals := make(chan os.Signal, 1)
		signal.Notify(exitSignals, syscall.SIGTERM, syscall.SIGINT)

		<-exitSignals
		cancel()
	}()

	exitStatus, err := run(ctx, opt)
	if err != nil {
		// exit with the same exit status as the failed command:
		if exitStatus != 0 {
			fmt.Fprintln(os.Stderr, utils.UserMessageFromError(err))
			os.Exit(exitStatus)
		}

		utils.FatalError(err)
	}
}

func run(ctx context.Context, opt option) (int, error) {
	// split login & host
	var user, host string
	for _, location := range opt.CopySpec {
		// Extract username and host from "username@host:file/path"
		parts := strings.Split(location, ":")
		parts = strings.Split(parts[0], "@")
		if len(parts) > 1 {
			user = parts[0]
			host = parts[1]
			break
		}
	}

	portStr := "22"
	if opt.Port != 0 {
		portStr = strconv.Itoa(int(opt.Port))
	}
	addr := net.JoinHostPort(host, portStr)

	flags := scp.Flags{
		Recursive:     opt.RecursiveCopy,
		PreserveAttrs: opt.PreserveAttrs,
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
	}

	err := client.SCP(ctx, opt.CopySpec, int(opt.Port), flags, opt.Quiet)
	return client.ExitStatus, err
}
