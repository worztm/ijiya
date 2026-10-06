//go:build windows

package report

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// enableVirtualTerminalProcessing is the console mode flag that makes the
// Windows console interpret ANSI escape sequences.
const enableVirtualTerminalProcessing = 0x0004

// EnableANSI turns on ANSI colour support for the current console. It is a
// no-op when stdout is redirected, when the call is unsupported, or on
// consoles that predate virtual terminal processing.
func EnableANSI() {
	handle := os.Stdout.Fd()
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return
	}
	// A failure here only means colour stays off, which the caller already
	// tolerates, so the result is deliberately discarded.
	_, _, _ = procSetConsoleMode.Call(handle, uintptr(mode|enableVirtualTerminalProcessing))
}
