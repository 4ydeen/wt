package main

import (
	"strings"
	"testing"
	"time"
)

func TestLinkWatchSilentClient(t *testing.T) {
	var w linkWatch
	var notes []string
	for i := 0; i < 20; i++ { // 200 s of packets out, none in, link not alive
		if n := w.tick(10*time.Second, 0, 5, false); n != "" {
			notes = append(notes, n)
		}
	}
	if len(notes) < 3 || len(notes) > 4 {
		t.Fatalf("want a line at 30 s then about once a minute, got %d: %v", len(notes), notes)
	}
	if !strings.Contains(notes[0], "no reply from the server since start") {
		t.Fatalf("first line should explain a never-answered client: %q", notes[0])
	}
}

func TestLinkWatchQuietWhenIdleOrAlive(t *testing.T) {
	var w linkWatch
	for i := 0; i < 30; i++ {
		if n := w.tick(10*time.Second, 0, 0, false); n != "" { // nothing sent: idle, not silent
			t.Fatalf("idle tunnel must not warn: %q", n)
		}
		if n := w.tick(10*time.Second, 0, 9, true); n != "" { // session says alive
			t.Fatalf("alive link must not warn: %q", n)
		}
	}
}

func TestLinkWatchLostThenRecovered(t *testing.T) {
	var w linkWatch
	in := uint64(0)
	for i := 0; i < 5; i++ { // healthy
		in += 100
		if n := w.tick(10*time.Second, in, 100, true); n != "" {
			t.Fatalf("healthy: %q", n)
		}
	}
	var got string
	for i := 0; i < 6; i++ { // answers stop, client keeps sending
		if n := w.tick(10*time.Second, in, 5, false); n != "" {
			got = n
		}
	}
	if !strings.Contains(got, "lost contact") {
		t.Fatalf("want a lost-contact line after the silence, got %q", got)
	}
	in++ // an answer arrives
	if n := w.tick(10*time.Second, in, 5, false); n != "" {
		t.Fatalf("recovery tick must be quiet: %q", n)
	}
	if w.silent != 0 {
		t.Fatalf("silence counter should reset, got %v", w.silent)
	}
}
