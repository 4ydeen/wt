package main

import "testing"

func TestLoopbackMetricsAddr(t *testing.T) {
	for _, c := range []struct {
		in, out string
		changed bool
	}{
		{"127.0.0.1:19700", "127.0.0.1:19700", false},
		{"127.5.5.5:1", "127.5.5.5:1", false},
		{"localhost:19700", "localhost:19700", false},
		{"[::1]:19700", "[::1]:19700", false},
		{":19700", "127.0.0.1:19700", true},
		{"0.0.0.0:19700", "127.0.0.1:19700", true},
		{"[::]:19700", "127.0.0.1:19700", true},
		{"192.168.1.5:19700", "127.0.0.1:19700", true},
		{"example.com:80", "127.0.0.1:80", true},
		{"19700", "127.0.0.1:19700", true}, // bare port
		{"a:b:c", "a:b:c", false},          // unparseable: left for ListenAndServe to report
	} {
		got, ch := loopbackMetricsAddr(c.in)
		if got != c.out || ch != c.changed {
			t.Errorf("%q: got %q,%v want %q,%v", c.in, got, ch, c.out, c.changed)
		}
	}
}

func TestIsMetricsPort(t *testing.T) {
	defer metricsPort.Store(0)
	metricsPort.Store(0)
	if isMetricsPort(19700) {
		t.Error("metrics off: nothing is the metrics port")
	}
	metricsPort.Store(19700)
	if !isMetricsPort(19700) || isMetricsPort(19701) || isMetricsPort(0) {
		t.Error("metrics port decision wrong")
	}
}
