module github.com/turingvideo/gossh/tool

go 1.16

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/rs/zerolog v1.23.0
	github.com/turingvideo/gossh v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e // indirect
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace github.com/turingvideo/gossh => ../
