package tui

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/leonardomb1/pulse/node"
)

// sparkline renders a slice of float64 values as a compact Unicode sparkline.
// Uses block characters ▁▂▃▄▅▆▇█ to represent values relative to the max.
func sparkline(values []float64, width int) string {
	bars := []rune("▁▂▃▄▅▆▇█")
	if len(values) == 0 {
		return ""
	}

	// Use the last `width` values.
	if len(values) > width {
		values = values[len(values)-width:]
	}

	maxVal := 0.0
	for _, v := range values {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	out := make([]rune, len(values))
	for i, v := range values {
		idx := int(v / maxVal * float64(len(bars)-1))
		if idx >= len(bars) {
			idx = len(bars) - 1
		}
		if idx < 0 {
			idx = 0
		}
		out[i] = bars[idx]
	}
	return string(out)
}

func (a *App) renderDashboard() {
	t := a.dashboardTable
	t.Clear()

	headers := []string{"NODE ID", "NAME", "LATENCY", "LOSS", "LATENCY HISTORY", "LOSS HISTORY"}
	if a.isScribe {
		headers = append(headers, "TX RATE", "RX RATE")
	}
	for i, h := range headers {
		t.SetCell(0, i, headerCell(h))
	}

	// Parse stats ring data from control socket.
	var allLatest map[string]node.StatsSnapshot
	if resp, err := ctrlDo(a.socketPath, map[string]string{"cmd": "peer-stats"}); err == nil {
		_ = json.Unmarshal(resp["latest"], &allLatest)
	}

	// Fetch per-peer time series.
	type peerSeries struct {
		nodeID    string
		name      string
		latencies []float64
		losses    []float64
		latest    node.StatsSnapshot
	}

	var peers []peerSeries
	for _, p := range a.peers {
		if p.NodeID == a.selfID {
			continue
		}
		ps := peerSeries{
			nodeID: p.NodeID,
			name:   p.Name,
		}
		if ps.name == "" {
			ps.name = p.NodeID[:min(8, len(p.NodeID))]
		}

		// Fetch time series for this peer.
		if resp, err := ctrlDo(a.socketPath, map[string]interface{}{"cmd": "peer-stats", "node_id": p.NodeID}); err == nil {
			var snaps []node.StatsSnapshot
			_ = json.Unmarshal(resp["snapshots"], &snaps)
			for _, s := range snaps {
				ps.latencies = append(ps.latencies, s.LatencyMS)
				ps.losses = append(ps.losses, s.LossRate*100)
			}
		}
		if s, ok := allLatest[p.NodeID]; ok {
			ps.latest = s
		}
		peers = append(peers, ps)
	}

	// Sort by latency (lowest first).
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].latest.LatencyMS < peers[j].latest.LatencyMS
	})

	for i, ps := range peers {
		row := i + 1

		latStr := "-"
		if ps.latest.LatencyMS > 0 && !math.IsInf(ps.latest.LatencyMS, 0) {
			latStr = fmt.Sprintf("%.1fms", ps.latest.LatencyMS)
		}
		lossStr := fmt.Sprintf("%.0f%%", ps.latest.LossRate*100)

		latSpark := sparkline(ps.latencies, 20)
		lossSpark := sparkline(ps.losses, 20)

		sparkColor := tcell.ColorAqua
		if ps.latest.LossRate > 0.1 {
			sparkColor = tcell.ColorYellow
		}
		if ps.latest.LossRate > 0.5 {
			sparkColor = tcell.ColorRed
		}

		col := 0
		set := func(c *tview.TableCell) { t.SetCell(row, col, c); col++ }

		set(dataCell(ps.nodeID[:min(8, len(ps.nodeID))]))
		set(dataCell(ps.name))
		set(dataCell(latStr))
		set(dataCell(lossStr))
		set(tview.NewTableCell(latSpark).SetTextColor(sparkColor).SetExpansion(1))
		set(tview.NewTableCell(lossSpark).SetTextColor(sparkColor).SetExpansion(1))

		if a.isScribe {
			set(dataCell(formatBytes(ps.latest.BytesOut)))
			set(dataCell(formatBytes(ps.latest.BytesIn)))
		}
	}
}
