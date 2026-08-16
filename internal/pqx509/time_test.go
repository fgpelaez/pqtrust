package pqx509

import (
	"testing"
	"time"
)

func TestMarshalTimeChoosesEncodingByYear(t *testing.T) {
	cases := []struct {
		in      time.Time
		wantTag int // 23 = UTCTime, 24 = GeneralizedTime
	}{
		{time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), 23},
		{time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), 23},
		{time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), 24},
		{time.Date(2075, 6, 1, 0, 0, 0, 0, time.UTC), 24},
	}
	for _, c := range cases {
		rv, err := marshalTime(c.in)
		if err != nil {
			t.Fatalf("marshalTime(%v): %v", c.in, err)
		}
		if rv.Tag != c.wantTag {
			t.Errorf("marshalTime(%v) tag = %d, want %d", c.in, rv.Tag, c.wantTag)
		}
		back, err := parseTime(rv)
		if err != nil {
			t.Fatalf("parseTime: %v", err)
		}
		if !back.Equal(c.in) {
			t.Errorf("round-trip = %v, want %v", back, c.in)
		}
	}
}

func TestMarshalTimeTruncatesSubSecondAndNormalizesZone(t *testing.T) {
	loc := time.FixedZone("UTC+2", 2*3600)
	in := time.Date(2030, 3, 4, 5, 6, 7, 999_000_000, loc)
	rv, err := marshalTime(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseTime(rv)
	if err != nil {
		t.Fatal(err)
	}
	want := in.Truncate(time.Second).UTC()
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got.Location() != time.UTC {
		t.Errorf("parsed time must be UTC, got %v", got.Location())
	}
}
