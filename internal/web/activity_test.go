package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kivraid/kivraid/internal/audit"
	"github.com/kivraid/kivraid/internal/store/sqlcgen"
)

func TestBuildSignInSeries(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC)
	events := []sqlcgen.ListSignInEventsSinceRow{
		{Ts: now.Add(-time.Hour), Action: audit.ActionLogin},
		{Ts: now.Add(-2 * time.Hour), Action: audit.ActionLoginFailed},
		{Ts: now.Add(-3 * 24 * time.Hour), Action: audit.ActionLogin},
		{Ts: now.Add(-30 * 24 * time.Hour), Action: audit.ActionLogin}, // outside the window
	}
	series, ok24, fail24 := buildSignInSeries(now, events)
	if len(series.OK) != signInChartHours || len(series.Fail) != signInChartHours {
		t.Fatalf("want %d hourly buckets, got %d/%d", signInChartHours, len(series.OK), len(series.Fail))
	}
	if series.Start != now.Truncate(time.Hour).Add(-(signInChartHours-1)*time.Hour).Unix() {
		t.Error("series should start on an hour boundary, signInChartHours before now")
	}
	var ok, fail int64
	for i := range series.OK {
		ok += series.OK[i]
		fail += series.Fail[i]
	}
	if ok != 2 || fail != 1 || ok24 != 1 || fail24 != 1 {
		t.Fatalf("counts: window %d ok/%d fail, 24h %d ok/%d fail", ok, fail, ok24, fail24)
	}
}

func TestActivityFiltersAndLabels(t *testing.T) {
	ts, st, c, _ := adminClient(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	for _, e := range []sqlcgen.InsertAuditParams{
		{Ts: time.Now().UTC(), Actor: "mallory", Action: audit.ActionLoginFailed, Ip: "203.0.113.9"},
		{Ts: old, Actor: "oldtimer", Action: audit.ActionLogin, Ip: "198.51.100.1"},
	} {
		if err := st.InsertAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	_, body := getPage(t, c, ts.URL+"/admin/audit")
	if !strings.Contains(body, "Sign-in failed") || !strings.Contains(body, "tone-danger") {
		t.Error("failed sign-ins should show a readable, highlighted label")
	}
	if !strings.Contains(body, `href="/admin/audit?ip=203.0.113.9"`) {
		t.Error("IP addresses should link to an IP filter")
	}

	_, body = getPage(t, c, ts.URL+"/admin/audit?ip=203.0.113.9")
	if !strings.Contains(body, "mallory") || strings.Contains(body, "oldtimer") {
		t.Error("ip filter should keep only that address")
	}
	_, body = getPage(t, c, ts.URL+"/admin/audit?range=7d")
	if strings.Contains(body, "oldtimer") || !strings.Contains(body, "mallory") {
		t.Error("range=7d should drop events older than a week")
	}
	if _, body = getPage(t, c, ts.URL+"/admin"); !strings.Contains(body, "data-signin-chart") {
		t.Error("dashboard should include the sign-in chart")
	}
}
