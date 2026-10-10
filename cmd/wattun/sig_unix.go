//go:build !windows

package main

import (
	"os"
	"syscall"
)

// drainSignal is SIGUSR1: stop taking new client sessions and exit once the current ones are gone.
var drainSignal os.Signal = syscall.SIGUSR1
