package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/leonardomb1/pulse/node"
)

// App is the TUI application.
type App struct {
	app        *tview.Application
	socketPath string

	// Layout
	pages     *tview.Pages
	topBar    *tview.TextView
	bottomBar *tview.TextView

	// Views
	nodesTable *tview.Table
	dnsTable   *tview.Table
	routeTable *tview.Table
	aclTable   *tview.Table

	// State
	selfID    string
	networkID string
	isScribe  bool
	peers     []node.PeerEntry
	dns       []node.DNSZone
	routes    []routeEntry
	acls      []node.ACLRule
	stats     map[string]node.NodeStats
}

type routeEntry struct {
	CIDR   string `json:"cidr"`
	NodeID string `json:"node_id"`
	Auto   bool   `json:"auto,omitempty"`
}

// New creates a new TUI app connected to the given control socket.
func New(socketPath string) *App {
	return &App{socketPath: socketPath}
}

// Run starts the TUI. Blocks until the user quits.
func (a *App) Run() error {
	a.app = tview.NewApplication()

	// Top bar
	a.topBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	a.topBar.SetBackgroundColor(tcell.ColorDarkGreen)

	// Bottom bar
	a.bottomBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	a.bottomBar.SetBackgroundColor(tcell.ColorDarkSlateGray)

	// Views
	a.nodesTable = a.makeTable()
	a.dnsTable = a.makeTable()
	a.routeTable = a.makeTable()
	a.aclTable = a.makeTable()

	// Pages
	a.pages = tview.NewPages().
		AddPage("nodes", a.nodesTable, true, true).
		AddPage("dns", a.dnsTable, true, false).
		AddPage("routes", a.routeTable, true, false).
		AddPage("acls", a.aclTable, true, false)

	// Layout
	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.topBar, 1, 0, false).
		AddItem(a.pages, 0, 1, true).
		AddItem(a.bottomBar, 1, 0, false)

	// Global keys
	a.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case '1':
			a.switchPage("nodes")
			return nil
		case '2':
			a.switchPage("dns")
			return nil
		case '3':
			a.switchPage("routes")
			return nil
		case '4':
			a.switchPage("acls")
			return nil
		case 'q':
			a.app.Stop()
			return nil
		}
		// Page-specific keys
		page, _ := a.pages.GetFrontPage()
		switch page {
		case "nodes":
			return a.handleNodesKey(event)
		case "dns":
			return a.handleDNSKey(event)
		case "routes":
			return a.handleRoutesKey(event)
		case "acls":
			return a.handleACLsKey(event)
		}
		return event
	})

	// Initial fetch + render
	a.refresh()
	a.renderCurrentPage()

	// Background polling
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			a.refresh()
			a.app.QueueUpdateDraw(func() {
				a.renderCurrentPage()
			})
		}
	}()

	return a.app.SetRoot(layout, true).EnableMouse(false).Run()
}

func (a *App) makeTable() *tview.Table {
	t := tview.NewTable().
		SetFixed(1, 0).
		SetSelectable(true, false).
		SetBorders(false)
	t.SetBackgroundColor(tcell.ColorDefault)
	return t
}

func (a *App) switchPage(name string) {
	a.pages.SwitchToPage(name)
	a.renderCurrentPage()
}

func (a *App) renderCurrentPage() {
	page, _ := a.pages.GetFrontPage()
	switch page {
	case "nodes":
		a.renderNodes()
	case "dns":
		a.renderDNS()
	case "routes":
		a.renderRoutes()
	case "acls":
		a.renderACLs()
	}
	a.renderTopBar(page)
	a.renderBottomBar(page)
}

func (a *App) refresh() {
	// Status
	if resp, err := ctrlDo(a.socketPath, map[string]string{"cmd": "status"}); err == nil {
		_ = json.Unmarshal(resp["self"], &a.selfID)
		_ = json.Unmarshal(resp["peers"], &a.peers)
		_ = json.Unmarshal(resp["network_id"], &a.networkID)
		if statsRaw, ok := resp["stats"]; ok {
			_ = json.Unmarshal(statsRaw, &a.stats)
		}
	}

	// Check if scribe
	a.isScribe = false
	for _, p := range a.peers {
		if p.NodeID == a.selfID && p.IsScribe {
			a.isScribe = true
		}
	}

	// DNS
	if resp, err := ctrlDo(a.socketPath, map[string]string{"cmd": "dns-list"}); err == nil {
		_ = json.Unmarshal(resp["zones"], &a.dns)
	}

	// Routes
	if resp, err := ctrlDo(a.socketPath, map[string]string{"cmd": "route-list"}); err == nil {
		_ = json.Unmarshal(resp["routes"], &a.routes)
	}

	// ACLs
	if resp, err := ctrlDo(a.socketPath, map[string]string{"cmd": "acl-list"}); err == nil {
		_ = json.Unmarshal(resp["rules"], &a.acls)
	}
}

func (a *App) renderTopBar(page string) {
	if a.selfID == "" {
		a.topBar.SetText(" [white:darkgreen:b]pulse[-:-:-] connecting...")
		return
	}
	meshIP := node.MeshIPFromNodeID(a.selfID)
	roles := ""
	for _, p := range a.peers {
		if p.NodeID == a.selfID {
			if p.IsCA {
				roles += " CA"
			}
			if p.IsScribe {
				roles += " scribe"
			}
			if p.IsExit {
				roles += " exit"
			}
			break
		}
	}
	if roles == "" {
		roles = " relay"
	}

	peerCount := 0
	for _, p := range a.peers {
		if p.NodeID != a.selfID {
			peerCount++
		}
	}

	tabs := []struct{ key, name string }{
		{"1", "Nodes"}, {"2", "DNS"}, {"3", "Routes"}, {"4", "ACLs"},
	}
	var tabStr string
	for _, t := range tabs {
		if strings.ToLower(t.name) == page {
			tabStr += fmt.Sprintf(" [black:green] %s %s [-:-] ", t.key, t.name)
		} else {
			tabStr += fmt.Sprintf(" [white:-] %s %s [-:-] ", t.key, t.name)
		}
	}

	netLabel := ""
	if a.networkID != "" {
		netLabel = " " + a.networkID
	}

	a.topBar.SetText(fmt.Sprintf(" [white:darkgreen:b]pulse[-:-:-] %s %s%s%s %d peers  %s",
		a.selfID[:min(8, len(a.selfID))], meshIP, netLabel, roles, peerCount, tabStr))
}

func (a *App) renderBottomBar(page string) {
	switch page {
	case "nodes":
		if a.isScribe {
			a.bottomBar.SetText(" [yellow]t[white]:tag  [yellow]n[white]:name  [yellow]r[white]:revoke  [yellow]q[white]:quit")
		} else {
			a.bottomBar.SetText(" [yellow]q[white]:quit  [dim](read-only: not the scribe)")
		}
	case "dns":
		if a.isScribe {
			a.bottomBar.SetText(" [yellow]a[white]:add  [yellow]d[white]:delete  [yellow]q[white]:quit")
		} else {
			a.bottomBar.SetText(" [yellow]q[white]:quit  [dim](read-only: not the scribe)")
		}
	case "routes":
		a.bottomBar.SetText(" [yellow]a[white]:add  [yellow]d[white]:delete  [yellow]q[white]:quit")
	case "acls":
		if a.isScribe {
			a.bottomBar.SetText(" [yellow]a[white]:add  [yellow]d[white]:delete  [yellow]q[white]:quit")
		} else {
			a.bottomBar.SetText(" [yellow]q[white]:quit  [dim](read-only: not the scribe)")
		}
	}
}

func headerCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).
		SetTextColor(tcell.ColorYellow).
		SetSelectable(false).
		SetExpansion(1)
}

func dataCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).
		SetTextColor(tcell.ColorWhite).
		SetExpansion(1)
}

func dimCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).
		SetTextColor(tcell.ColorGray).
		SetExpansion(1)
}
