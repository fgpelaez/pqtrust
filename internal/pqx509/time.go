package pqx509

import (
	"encoding/asn1"
	"fmt"
	"time"
)

const (
	tagUTCTime         = 23
	tagGeneralizedTime = 24
)

// marshalTime encodes t per RFC 5280 4.1.2.5: UTCTime through 2049,
// GeneralizedTime from 2050 on. Seconds are always present; the zone is Z.
func marshalTime(t time.Time) (asn1.RawValue, error) {
	u := t.UTC().Truncate(time.Second)
	var der []byte
	var err error
	if u.Year() < 2050 {
		der, err = asn1.MarshalWithParams(u, "utc")
	} else {
		der, err = asn1.MarshalWithParams(u, "generalized")
	}
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: marshaling time %v: %w", t, err)
	}
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return asn1.RawValue{}, fmt.Errorf("pqx509: re-reading marshaled time: %w", err)
	}
	return rv, nil
}

// parseTime decodes a UTCTime or GeneralizedTime raw value into a UTC time.
func parseTime(rv asn1.RawValue) (time.Time, error) {
	var t time.Time
	var params string
	switch rv.Tag {
	case tagUTCTime:
		params = "utc"
	case tagGeneralizedTime:
		params = "generalized"
	default:
		return time.Time{}, fmt.Errorf("%w: time has tag %d, want 23 or 24", ErrMalformedDER, rv.Tag)
	}
	rest, err := asn1.UnmarshalWithParams(rv.FullBytes, &t, params)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: time: %w", ErrMalformedDER, err)
	}
	if len(rest) != 0 {
		return time.Time{}, fmt.Errorf("%w: %d bytes after time", ErrTrailingData, len(rest))
	}
	return t.UTC(), nil
}
