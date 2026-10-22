//go:build windows

package main

import "os"

// drainSignal is nil on Windows: the OS has no second catchable signal distinct from Ctrl+C
// (Go delivers both console events as os.Interrupt), so the drain handover stays a Linux
// SIGUSR1 feature and Ctrl+C always means save-and-exit. Registering os.Interrupt here too
// made the first Ctrl+C race the drain goroutine against immediate shutdown.
var drainSignal os.Signal
