package tui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func (a *App) renderRoutes() {
	t := a.routeTable
	t.Clear()

	headers := []string{"CIDR", "EXIT NODE", "SOURCE"}
	for i, h := range headers {
		t.SetCell(0, i, headerCell(h))
	}

	if len(a.routes) == 0 {
		t.SetCell(1, 0, dimCell("No exit routes"))
		return
	}

	for i, r := range a.routes {
		row := i + 1
		source := "manual"
		if r.Auto {
			source = "auto (gossip)"
		}
		t.SetCell(row, 0, dataCell(r.CIDR))
		t.SetCell(row, 1, dataCell(r.NodeID))
		t.SetCell(row, 2, dimCell(source))
	}
}

func (a *App) handleRoutesKey(event *tcell.EventKey) *tcell.EventKey {
	switch event.Rune() {
	case 'a': // add
		a.showRouteAddForm()
		return nil
	case 'd': // delete
		row, _ := a.routeTable.GetSelection()
		idx := row - 1
		if idx >= 0 && idx < len(a.routes) {
			r := a.routes[idx]
			a.showConfirmModal(fmt.Sprintf("Remove route %s?", r.CIDR), func() {
				_, _ = ctrlDo(a.socketPath, map[string]string{"cmd": "route-remove", "cidr": r.CIDR})
				a.refresh()
				a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
			})
		}
		return nil
	}
	return event
}

func (a *App) showRouteAddForm() {
	form := tview.NewForm().
		AddInputField("CIDR", "", 25, nil, nil).
		AddInputField("Via (node ID)", "", 25, nil, nil)

	form.AddButton("Add", func() {
		cidr := form.GetFormItemByLabel("CIDR").(*tview.InputField).GetText()
		via := form.GetFormItemByLabel("Via (node ID)").(*tview.InputField).GetText()
		a.pages.RemovePage("route-add")

		if cidr == "" || via == "" {
			return
		}
		go func() {
			_, _ = ctrlDo(a.socketPath, map[string]string{"cmd": "route-add", "cidr": cidr, "via": via})
			a.refresh()
			a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
		}()
	})

	form.AddButton("Cancel", func() {
		a.pages.RemovePage("route-add")
	})

	form.SetBorder(true).SetTitle(" Add Route ").SetTitleAlign(tview.AlignCenter)
	form.SetBackgroundColor(tcell.ColorDarkSlateGray)

	a.pages.AddPage("route-add", center(form, 45, 11), true, true)
}
