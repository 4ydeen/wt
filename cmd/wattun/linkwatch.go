package main

// Link watch: turns "sending but hearing nothing back" into a plain log line.
//
// A client whose packets go out but never come back (replies filtered on the way, wrong key or carrier, the server
// not running) used to show only `out=5 in=0 retrans=5` every 10 s, which looks like a working-but-idle tunnel.
// The watch counts silent ticks and says what is going on, once a minute, until something arrives again.

import "time"

const (
	silentWarnAfter = 30 * time.Second // client: sent traffic, nothing received, for this long
	silentRepeat    = 60 * time.Second // then repeat the line at most this often
)

type linkWatch struct {
	lastIn   uint64        // PktsIn at the previous tick
	silent   time.Duration // how long PktsIn has not moved while the client kept sending
	nextNote time.Duration // silent time at which the next line may be printed
	everRecv bool          // anything at all has been received since the process started
}

// tick is called every interval with the cumulative counters. It returns a log line, or "".
// outDelta is the packets sent during the interval; alive is the session's own link state.
func (w *linkWatch) tick(interval time.Duration, pktsIn, outDelta uint64, alive bool) string {
	if pktsIn > w.lastIn {
		w.lastIn = pktsIn
		w.everRecv = true
		w.silent, w.nextNote = 0, silentWarnAfter
		return ""
	}
	if outDelta == 0 || alive { // idle (nothing was sent) or the link says it is fine: not a silence
		w.silent, w.nextNote = 0, silentWarnAfter
		return ""
	}
	w.silent += interval
	if w.nextNote == 0 {
		w.nextNote = silentWarnAfter
	}
	if w.silent < w.nextNote {
		return ""
	}
	w.nextNote = w.silent + silentRepeat
	if !w.everRecv {
		return "no reply from the server since start: packets go out but nothing comes back. Likely causes: the server is not " +
			"running, the key or carrier/icmp-type differs on the two sides, or the server's answers are filtered on the way " +
			"back (try wattun-manager Diagnose)"
	}
	return "lost contact: the server has been silent for " + w.silent.Round(time.Second).String() +
		" while packets keep going out. The route is probably blocking the answers right now; the tunnel reconnects by itself when they return"
}
