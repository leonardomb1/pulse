package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/leonardomb1/pulse/node"
)

func (a *App) renderNodes() {
	t := a.nodesTable
	t.Clear()

	headers := []string{"NODE ID", "NAME", "MESH IP", "ADDR", "LINK", "LATENCY", "LOSS", "HOPS", "VER", "ROLES", "TAGS", "LAST SEEN"}
	if a.isScribe {
		headers = append(headers, "TX", "RX", "CONNS")
	}
	for i, h := range headers {
		t.SetCell(0, i, headerCell(h))
	}

	for i, p := range a.peers {
		row := i + 1
		isSelf := p.NodeID == a.selfID

		id := p.NodeID
		if isSelf {
			id += " *"
		}

		meshIP := p.MeshIP
		if meshIP == "" {
			meshIP = node.MeshIPFromNodeID(p.NodeID).String()
		}

		name := p.Name
		if name == "" {
			name = "-"
		}

		linkType := "-"
		if p.LinkType != "" {
			linkType = p.LinkType
		}

		latency := "-"
		if p.LatencyMS > 0 && p.LatencyMS < 1e15 {
			latency = fmt.Sprintf("%.1fms", p.LatencyMS)
		}

		loss := fmt.Sprintf("%.0f%%", p.LossRate*100)

		roles := roleString(p)

		tags := "-"
		if len(p.Tags) > 0 {
			tags = strings.Join(p.Tags, ",")
		}

		lastSeen := "-"
		if !p.LastSeen.IsZero() {
			lastSeen = time.Since(p.LastSeen).Round(time.Second).String()
		}

		cellFn := dataCell
		linkCellFn := cellFn
		if isSelf {
			cellFn = func(text string) *tview.TableCell {
				return tview.NewTableCell(text).
					SetTextColor(tcell.ColorGreen).
					SetExpansion(1)
			}
			linkCellFn = cellFn
		} else {
			switch linkType {
			case "direct_quic":
				linkCellFn = func(text string) *tview.TableCell {
					return tview.NewTableCell(text).
						SetTextColor(tcell.ColorLimeGreen).
						SetExpansion(1)
				}
			case "quic":
				linkCellFn = func(text string) *tview.TableCell {
					return tview.NewTableCell(text).
						SetTextColor(tcell.ColorAqua).
						SetExpansion(1)
				}
			case "websocket":
				linkCellFn = func(text string) *tview.TableCell {
					return tview.NewTableCell(text).
						SetTextColor(tcell.ColorYellow).
						SetExpansion(1)
				}
			}
		}

		col := 0
		set := func(c *tview.TableCell) { t.SetCell(row, col, c); col++ }

		set(cellFn(id))
		set(cellFn(name))
		set(cellFn(meshIP))
		set(cellFn(p.Addr))
		set(linkCellFn(linkType))
		set(cellFn(latency))
		set(cellFn(loss))
		set(cellFn(fmt.Sprint(p.HopCount)))
		ver := p.Version
		if ver == "" {
			ver = "-"
		}
		set(dimCell(ver))
		set(cellFn(roles))
		set(cellFn(tags))
		set(dimCell(lastSeen))

		if a.isScribe {
			if st, ok := a.stats[p.NodeID]; ok {
				set(cellFn(formatBytes(st.BytesOut)))
				set(cellFn(formatBytes(st.BytesIn)))
				set(cellFn(fmt.Sprint(st.ActiveConns)))
			} else {
				set(dimCell("-"))
				set(dimCell("-"))
				set(dimCell("-"))
			}
		}
	}
}

// formatBytes returns a human-readable byte count (e.g. "1.2 MB").
func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func (a *App) handleNodesKey(event *tcell.EventKey) *tcell.EventKey {
	if !a.isScribe {
		return event
	}
	row, _ := a.nodesTable.GetSelection()
	idx := row - 1 // skip header
	if idx < 0 || idx >= len(a.peers) {
		return event
	}
	peer := a.peers[idx]

	switch event.Rune() {
	case 't': // tag
		a.showInputModal("Tag node "+peer.NodeID[:8], "Tag:", func(tag string) {
			_, _ = ctrlDo(a.socketPath, map[string]string{"cmd": "tag-add", "node_id": peer.NodeID, "tag": tag})
			a.refresh()
			a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
		})
		return nil
	case 'n': // name
		a.showInputModal("Name node "+peer.NodeID[:8], "Name:", func(name string) {
			_, _ = ctrlDo(a.socketPath, map[string]string{"cmd": "name-set", "node_id": peer.NodeID, "name": name})
			a.refresh()
			a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
		})
		return nil
	case 'r': // revoke
		a.showConfirmModal("Revoke node "+peer.NodeID+"?", func() {
			_, _ = ctrlDo(a.socketPath, map[string]string{"cmd": "revoke", "node_id": peer.NodeID})
			a.refresh()
			a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
		})
		return nil
	}
	return event
}

func roleString(p node.PeerEntry) string {
	var parts []string
	if p.IsCA {
		parts = append(parts, "CA")
	}
	if p.IsScribe {
		parts = append(parts, "scribe")
	}
	if p.IsExit {
		parts = append(parts, "exit")
	}
	if len(parts) == 0 {
		return "relay"
	}
	return strings.Join(parts, ",")
}

func (a *App) showInputModal(title, label string, onDone func(string)) {
	input := tview.NewInputField().
		SetLabel(label + " ").
		SetFieldWidth(30)

	form := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetText(title).SetTextAlign(tview.AlignCenter), 1, 0, false).
		AddItem(input, 1, 0, true)

	frame := tview.NewFrame(form).
		SetBorders(1, 1, 1, 1, 2, 2)
	frame.SetBackgroundColor(tcell.ColorDarkSlateGray)
	frame.SetBorder(true)

	a.pages.AddPage("modal", center(frame, 50, 7), true, true)

	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			val := input.GetText()
			a.pages.RemovePage("modal")
			if val != "" {
				go onDone(val)
			}
		} else if key == tcell.KeyEscape {
			a.pages.RemovePage("modal")
		}
	})
}

func (a *App) showConfirmModal(text string, onConfirm func()) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{"Yes", "No"}).
		SetDoneFunc(func(idx int, label string) {
			a.pages.RemovePage("confirm")
			if label == "Yes" {
				go onConfirm()
			}
		})
	a.pages.AddPage("confirm", modal, true, true)
}

func center(p tview.Primitive, width, height int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, height, 1, true).
			AddItem(nil, 0, 1, false), width, 1, true).
		AddItem(nil, 0, 1, false)
}
