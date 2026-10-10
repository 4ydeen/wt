//go:build windows

package main

import "os"

var drainSignal os.Signal = os.Interrupt
