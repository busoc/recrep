package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/midbel/cli"
)

var errDone = errors.New("done!!!")

const helpText = `{{.Name}} capture and replay TM/PP packets from multicast stream

Usage:

  {{.Name}} command [arguments]

The commands are:

{{range .Commands}}{{printf "  %-9s %s" .String .Short}}
{{end}}

Use {{.Name}} [command] -h for more information about its usage.
`

const Version = "1.0"

const BufferSize = 4096 * 4

var commands = []*cli.Command{
	capture,
	replay,
	sim,
	list,
}

func main() {
	log.SetFlags(0)
	usage := func() {
		data := struct {
			Name     string
			Commands []*cli.Command
		}{
			Name:     filepath.Base(os.Args[0]),
			Commands: commands,
		}
		t := template.Must(template.New("help").Parse(helpText))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, nil); err != nil {
		log.Fatalln(err)
	}
}
