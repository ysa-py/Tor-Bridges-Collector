package ooni

import "testing"

func TestLatestMeasurementAtPreservesNewestOriginalTimestamp(t *testing.T) {
	measurements := []Measurement{
		{MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{TestStartTime: "2026-10-08T10:30:00+01:00"}, // 09:30 UTC
		{MeasurementStartTime: "2026-10-08T10:00:00.125Z", TestStartTime: "2026-10-08T11:00:00Z"},
		{MeasurementStartTime: "not-a-timestamp"},
	}

	got := latestMeasurementAt(measurements)
	want := "2026-10-08T10:00:00.125Z"
	if got != want {
		t.Fatalf("latestMeasurementAt() = %q, want original timestamp %q", got, want)
	}
}

func TestLatestMeasurementAtDoesNotInventTime(t *testing.T) {
	for _, measurements := range [][]Measurement{
		{},
		{{MeasurementStartTime: "not-a-timestamp"}},
		{{TestStartTime: ""}},
	} {
		if got := latestMeasurementAt(measurements); got != "" {
			t.Fatalf("latestMeasurementAt(%#v) = %q, want empty for missing or invalid time", measurements, got)
		}
	}
}

func TestClassifyRecentStatusUsesNewestTimestampedMeasurement(t *testing.T) {
	measurements := []Measurement{
		{Confirmed: true, MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{Confirmed: false, Anomaly: false, MeasurementStartTime: "2026-10-08T10:00:00.125Z"},
		{Confirmed: true, MeasurementStartTime: "not-a-timestamp"},
	}
	if got := classifyRecentStatus(measurements); got != StatusLikelyWorking {
		t.Fatalf("classifyRecentStatus() = %q, want %q from newest clean measurement", got, StatusLikelyWorking)
	}
}

func TestClassifyRecentStatusNewestAnomalyIsBlocked(t *testing.T) {
	measurements := []Measurement{
		{Confirmed: false, Anomaly: false, MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{Anomaly: true, MeasurementStartTime: "2026-10-08T11:00:00Z"},
	}
	if got := classifyRecentStatus(measurements); got != StatusLikelyBlocked {
		t.Fatalf("classifyRecentStatus() = %q, want %q from newest anomaly", got, StatusLikelyBlocked)
	}
}

func TestClassifyRecentStatusMissingTimestampsStayUnknown(t *testing.T) {
	measurements := []Measurement{{Confirmed: true, Anomaly: true}}
	if got := classifyRecentStatus(measurements); got != StatusUnknown {
		t.Fatalf("classifyRecentStatus() = %q, want %q when original time is missing", got, StatusUnknown)
	}
}

func TestTimestampedAnomalyCountIgnoresUntimestampedRows(t *testing.T) {
	measurements := []Measurement{
		{Confirmed: true},
		{Anomaly: true, MeasurementStartTime: "2026-10-08T09:00:00Z"},
		{Confirmed: false, Anomaly: false, MeasurementStartTime: "2026-10-08T10:00:00Z"},
	}
	if got := timestampedAnomalyCount(measurements); got != 1 {
		t.Fatalf("timestampedAnomalyCount() = %d, want 1 timestamped anomaly", got)
	}
}
