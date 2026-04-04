package tui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/leonardomb1/pulse/node"
)

func (a *App) renderACLs() {
	t := a.aclTable
	t.Clear()

	headers := []string{"#", "ACTION", "FROM", "TO", "PORTS"}
	for i, h := range headers {
		t.SetCell(0, i, headerCell(h))
	}

	if len(a.acls) == 0 {
		t.SetCell(1, 0, dimCell("No ACL rules (open by default)"))
		return
	}

	for i, r := range a.acls {
		row := i + 1
		action := r.Action
		if action == "" {
			action = "allow"
		}
		src := r.SrcPattern
		if src == "" {
			src = "*"
		}

		actionCell := dataCell(action)
		if action == "deny" {
			actionCell = tview.NewTableCell(action).
				SetTextColor(tcell.ColorRed).
				SetExpansion(1)
		}

		t.SetCell(row, 0, dimCell(fmt.Sprint(i)))
		t.SetCell(row, 1, actionCell)
		t.SetCell(row, 2, dataCell(src))
		t.SetCell(row, 3, dataCell(r.DstPattern))
		t.SetCell(row, 4, dimCell(node.FormatPortRanges(r.Ports)))
	}
}

func (a *App) handleACLsKey(event *tcell.EventKey) *tcell.EventKey {
	if !a.isScribe {
		return event
	}

	switch event.Rune() {
	case 'a': // add
		a.showACLAddForm()
		return nil
	case 'd': // delete
		row, _ := a.aclTable.GetSelection()
		idx := row - 1
		if idx >= 0 && idx < len(a.acls) {
			r := a.acls[idx]
			action := r.Action
			if action == "" {
				action = "allow"
			}
			a.showConfirmModal(fmt.Sprintf("Remove ACL rule #%d (%s %s→%s)?", idx, action, r.SrcPattern, r.DstPattern), func() {
				ctrlDo(a.socketPath, map[string]interface{}{"cmd": "acl-remove", "index": idx})
				a.refresh()
				a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
			})
		}
		return nil
	}
	return event
}

func (a *App) showACLAddForm() {
	form := tview.NewForm().
		AddDropDown("Action", []string{"allow", "deny"}, 0, nil).
		AddInputField("From (source)", "*", 25, nil, nil).
		AddInputField("To (dest)", "*", 25, nil, nil).
		AddInputField("Ports", "", 20, nil, nil)

	form.AddButton("Add", func() {
		_, action := form.GetFormItemByLabel("Action").(*tview.DropDown).GetCurrentOption()
		from := form.GetFormItemByLabel("From (source)").(*tview.InputField).GetText()
		to := form.GetFormItemByLabel("To (dest)").(*tview.InputField).GetText()
		portsStr := form.GetFormItemByLabel("Ports").(*tview.InputField).GetText()
		a.pages.RemovePage("acl-add")

		go func() {
			ports, _ := node.ParsePortRanges(portsStr)
			rule := node.ACLRule{
				Action:     action,
				SrcPattern: from,
				DstPattern: to,
				Ports:      ports,
			}
			ctrlDo(a.socketPath, map[string]interface{}{"cmd": "acl-add", "acl_rule": rule})
			a.refresh()
			a.app.QueueUpdateDraw(func() { a.renderCurrentPage() })
		}()
	})

	form.AddButton("Cancel", func() {
		a.pages.RemovePage("acl-add")
	})

	form.SetBorder(true).SetTitle(" Add ACL Rule ").SetTitleAlign(tview.AlignCenter)
	form.SetBackgroundColor(tcell.ColorDarkSlateGray)

	a.pages.AddPage("acl-add", center(form, 50, 15), true, true)
}
