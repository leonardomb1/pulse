package main

import (
	"os"

	"github.com/leonardomb1/pulse/cli"
)

func main() {
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
		case "tag":
			cli.RunTag(os.Args[2:])
			return
		case "untag":
			cli.RunUntag(os.Args[2:])
			return
		case "name":
			cli.RunSetName(os.Args[2:])
			return
		case "acl":
			cli.RunACL(os.Args[2:])
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
		case "top":
			cli.RunTop(os.Args[2:])
			return
		case "setup":
			cli.RunSetup(os.Args[2:])
			return
		case "help", "--help", "-h":
			cli.PrintUsage()
			return
		}
	}
	cli.RunNode(os.Args[1:])
}
