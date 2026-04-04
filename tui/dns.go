package tui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/leonardomb1/pulse/node"
)

func (a *App) renderDNS() {
	t := a.dnsTable
	t.Clear()

	headers := []string{"NAME", "TYPE", "VALUE", "TTL"}
	for i, h := range headers {
		t.SetCell(0, i, headerCell(h))
	}

	if len(a.dns) == 0 {
		t.SetCell(1, 0, dimCell("No DNS records"))
		return
	}

	for i, z := range a.dns {
		row := i + 1
		t.SetCell(row, 0, dataCell(z.Name))
		t.SetCell(row, 1, dataCell(z.Type))
		t.SetCell(row, 2, dataCell(z.Value))
		t.SetCell(row, 3, dimCell(fmt.Sprint(z.TTL)))
	}
}

func (a *App) handleDNSKey(event *tcell.EventKey) *tcell.EventKey {
	if !a.isScribe {
		return event
	}

	switch event.Rune() {
	case 'a': // add
		a.showDNSAddForm()
		return nil
	case 'd': // delete
		row, _ := a.dnsTable.GetSelection()
		idx := row - 1
		if idx >= 0 && idx < len(a.dns) {
			z := a.dns[idx]
			a.showConfirmModal(fmt.Sprintf("Delete DNS record %s %s?", z.Name, z.Type), func() {
				ctrlDo(a.socketPath, map[string]string{"cmd": "dns-remove", "name": z.Name, "type": z.Type})
				a.refresh()
				a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
			})
		}
		return nil
	}
	return event
}

func (a *App) showDNSAddForm() {
	form := tview.NewForm().
		AddInputField("Name", "", 30, nil, nil).
		AddDropDown("Type", []string{"A", "CNAME", "TXT", "SRV"}, 0, nil).
		AddInputField("Value", "", 30, nil, nil).
		AddInputField("TTL", "300", 10, nil, nil)

	form.AddButton("Add", func() {
		name := form.GetFormItemByLabel("Name").(*tview.InputField).GetText()
		_, recType := form.GetFormItemByLabel("Type").(*tview.DropDown).GetCurrentOption()
		value := form.GetFormItemByLabel("Value").(*tview.InputField).GetText()
		ttl := form.GetFormItemByLabel("TTL").(*tview.InputField).GetText()
		a.pages.RemovePage("dns-add")

		if name == "" || value == "" {
			return
		}
		var ttlVal uint32 = 300
		fmt.Sscanf(ttl, "%d", &ttlVal)

		go func() {
			zone := node.DNSZone{Name: name, Type: recType, Value: value, TTL: ttlVal}
			ctrlDo(a.socketPath, map[string]interface{}{"cmd": "dns-add", "zone": zone})
			a.refresh()
			a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
		}()
	})

	form.AddButton("Cancel", func() {
		a.pages.RemovePage("dns-add")
	})

	form.SetBorder(true).SetTitle(" Add DNS Record ").SetTitleAlign(tview.AlignCenter)
	form.SetBackgroundColor(tcell.ColorDarkSlateGray)

	a.pages.AddPage("dns-add", center(form, 50, 15), true, true)
}
