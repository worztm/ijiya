//go:build !windows

package report

// EnableANSI is a no-op outside Windows: terminals there already speak ANSI.
func EnableANSI() {}
