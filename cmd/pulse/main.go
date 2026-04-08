package main

import (
	"fmt"
	"os"

	"github.com/leonardomb1/pulse/cli"
)

// Set by -ldflags at build time.
var version = "dev"

// commands maps subcommand names to their handler functions.
var commands = map[string]func([]string){
	"start":         cli.RunStart,
	"stop":          cli.RunStop,
	"status":        cli.RunStatus,
	"id":            cli.RunID,
	"token":         cli.RunToken,
	"join":          cli.RunJoin,
	"invite":        cli.RunInvite,
	"tag":           cli.RunTag,
	"untag":         cli.RunUntag,
	"mesh-ip":       cli.RunMeshIP,
	"name":          cli.RunSetName,
	"acl":           cli.RunACL,
	"pin":           cli.RunPin,
	"unpin":         cli.RunUnpin,
	"restart":       cli.RunRestart,
	"groups":        cli.RunGroups,
	"template":      cli.RunTemplate,
	"bulk":          cli.RunBulk,
	"revoke":        cli.RunRevoke,
	"route":         cli.RunRoute,
	"dns":           cli.RunDNS,
	"connect":       cli.RunConnect,
	"forward":       cli.RunForward,
	"cert":          cli.RunCert,
	"ca":            cli.RunCA,
	"stats":         cli.RunStats,
	"events":        cli.RunEvents,
	"logs":          cli.RunLogs,
	"top":           cli.RunTop,
	"completion":    cli.RunCompletion,
	"remote-config": cli.RunRemoteConfig,
}

func main() {
	cli.NodeVersion = version
	if len(os.Args) > 1 {
		arg := os.Args[1]

		// Version.
		switch arg {
		case "version", "--version", "-v":
			fmt.Println("pulse " + version)
			return
		case "help", "--help", "-h":
			cli.PrintUsage()
			return
		}

		// Known subcommand.
		if fn, ok := commands[arg]; ok {
			fn(os.Args[2:])
			return
		}

		// Unknown word (not a flag) — show help.
		if arg[0] != '-' {
			_, _ = fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", arg)
			cli.PrintUsage()
			os.Exit(1)
		}
	}
	cli.RunNode(os.Args[1:])
}
