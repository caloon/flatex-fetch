package main

import (
	"testing"
	"time"

	"github.com/welworx/flatex-fetch/internal/config"
	"github.com/welworx/flatex-fetch/internal/portal"
)

// TestListProfileNoStoredPassword covers listProfile's guard against a
// profile with no password (e.g. imported metadata never completed with a
// credential) — the one error path that never touches the portal.
func TestListProfileNoStoredPassword(t *testing.T) {
	p := config.Profile{Name: "main", Username: "alice", Domain: "flatex.at"}
	if err := listProfile(p, "", "", time.Now(), time.Now(), false, false, false); err == nil {
		t.Fatal("expected an error for a profile with no stored password")
	}
}

// TestListProfileHappyPath pins that listProfile logs in and lists through
// newPortalClient (the same seam fetchProfile uses), across all three output
// formats.
func TestListProfileHappyPath(t *testing.T) {
	f := &fakePortal{docs: []portal.Document{
		testDoc(0, "2026-01-05", "January"),
	}}
	installFakePortal(t, f)

	p := config.Profile{Name: "main", Username: "alice", Domain: "flatex.at", Password: "pw"}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)

	for _, format := range []struct{ csvOut, jsonOut bool }{
		{false, false}, {true, false}, {false, true},
	} {
		if err := listProfile(p, p.Password, "", from, to, format.csvOut, format.jsonOut, false); err != nil {
			t.Fatalf("listProfile(csv=%v, json=%v): %v", format.csvOut, format.jsonOut, err)
		}
	}
}
