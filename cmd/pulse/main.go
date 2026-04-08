package main

import (
	"fmt"
	"os"

	"github.com/leonardomb1/pulse/cli"
)

// Set by -ldflags at build time.
var version = "dev"

func main() {
	cli.NodeVersion = version
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "start":
			cli.RunStart(os.Args[2:])
			return
		case "stop":
			cli.RunStop(os.Args[2:])
			return
		case "status":
			cli.RunStatus(os.Args[2:])
			return
		case "id":
			cli.RunID(os.Args[2:])
			return
		case "token":
			cli.RunToken(os.Args[2:])
			return
		case "join":
			cli.RunJoin(os.Args[2:])
			return
		case "invite":
			cli.RunInvite(os.Args[2:])
			return
		case "tag":
			cli.RunTag(os.Args[2:])
			return
		case "untag":
			cli.RunUntag(os.Args[2:])
			return
		case "mesh-ip":
			cli.RunMeshIP(os.Args[2:])
			return
		case "name":
			cli.RunSetName(os.Args[2:])
			return
		case "acl":
			cli.RunACL(os.Args[2:])
			return
		case "restart":
			cli.RunRestart(os.Args[2:])
			return
		case "groups":
			cli.RunGroups(os.Args[2:])
			return
		case "template":
			cli.RunTemplate(os.Args[2:])
			return
		case "bulk":
			cli.RunBulk(os.Args[2:])
			return
		case "revoke":
			cli.RunRevoke(os.Args[2:])
			return
		case "route":
			cli.RunRoute(os.Args[2:])
			return
		case "dns":
			cli.RunDNS(os.Args[2:])
			return
		case "connect":
			cli.RunConnect(os.Args[2:])
			return
		case "forward":
			cli.RunForward(os.Args[2:])
			return
		case "cert":
			cli.RunCert(os.Args[2:])
			return
		case "ca":
			cli.RunCA(os.Args[2:])
			return
		case "stats":
			cli.RunStats(os.Args[2:])
			return
		case "events":
			cli.RunEvents(os.Args[2:])
			return
		case "logs":
			cli.RunLogs(os.Args[2:])
			return
		case "top":
			cli.RunTop(os.Args[2:])
			return
		case "completion":
			cli.RunCompletion(os.Args[2:])
			return
		case "setup":
			cli.RunSetup(os.Args[2:])
			return
		case "version", "--version", "-v":
			fmt.Println("pulse " + version)
			return
		case "help", "--help", "-h":
			cli.PrintUsage()
			return
		default:
			// Unknown subcommand — if it looks like a command (no dash prefix),
			// show help. Otherwise treat as a flag for RunNode.
			if os.Args[1][0] != '-' {
				fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
				cli.PrintUsage()
				os.Exit(1)
			}
		}
	}
	cli.RunNode(os.Args[1:])
}
