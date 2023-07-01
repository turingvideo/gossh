module github.com/turingvideo/gossh/tool

go 1.18

replace github.com/turingvideo/gossh => ../

require (
	github.com/rs/zerolog v1.29.1
	github.com/turingvideo/gossh v0.0.0-00010101000000-000000000000
	golang.org/x/term v0.9.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/gravitational/trace v1.2.1 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/crypto v0.10.0 // indirect
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
)
