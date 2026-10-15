package core

import (
	"strings"

	"github.com/alexeyco/simpletable"
)

const (
	tWhite      = "\033[97m"
	tTableWhite = "\033[0;97m"
	tReset      = "\033[0m"
	tGreen      = "\033[92m"
	tRed        = "\033[91m"
	tYel        = "\033[93m"
	tCyan       = "\033[96m"
	tPink       = "\033[95m"
)

func (s *Session) accent() string {
	return tWhite
}

// writeSimpleTable renders headers and rows with simpletable.StyleCompact ('=' rules, no title line).
func (s *Session) writeSimpleTable(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}
	if len(rows) == 0 {
		s.Writeln(tTableWhite + "No data to display." + tReset)
		s.Writeln("")
		return
	}

	tbl := simpletable.New()
	tbl.SetStyle(simpletable.StyleCompact)
	hc := make([]*simpletable.Cell, len(headers))
	for i, h := range headers {
		hc[i] = &simpletable.Cell{Align: simpletable.AlignLeft, Text: h}
	}
	tbl.Header = &simpletable.Header{Cells: hc}

	for _, r := range rows {
		row := append([]string(nil), r...)
		for len(row) < len(headers) {
			row = append(row, "")
		}
		if len(row) > len(headers) {
			row = row[:len(headers)]
		}
		rc := make([]*simpletable.Cell, len(headers))
		for j := 0; j < len(headers); j++ {
			rc[j] = &simpletable.Cell{Align: simpletable.AlignLeft, Text: row[j]}
		}
		tbl.Body.Cells = append(tbl.Body.Cells, rc)
	}

	out := strings.TrimRight(strings.ReplaceAll(tbl.String(), "\r\n", "\n"), "\n")
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			s.Writeln(tTableWhite + line + tReset)
		}
	}
	s.Writeln("")
}
