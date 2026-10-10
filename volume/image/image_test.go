package image

import "testing"

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"512": 512, "40M": 40 << 20, "1g": 1 << 30, "2GiB": 2 << 30, "300MB": 300 << 20, "1T": 1 << 40} {
		if got, err := ParseSize(in); got != want || err != nil {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "M", "-1", "0", "1.5G", "12Q"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
