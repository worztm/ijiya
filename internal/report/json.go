package report

import (
	"encoding/json"
	"io"
)

// WriteJSON renders the report as indented JSON.
func WriteJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}
