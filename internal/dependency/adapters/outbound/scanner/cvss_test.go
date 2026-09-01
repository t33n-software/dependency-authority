package scanner

import (
	"testing"
)

func TestCVSS3BaseScore(t *testing.T) {
	for _, tc := range []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
	} {
		t.Run(tc.vector, func(t *testing.T) {
			got, err := cvss3BaseScore(tc.vector)
			if err != nil {
				t.Fatalf("cvss3BaseScore() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("cvss3BaseScore() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCVSS3BaseScoreRejectsInvalidVectors(t *testing.T) {
	for name, vector := range map[string]string{
		"metric count":       "CVSS:3.1/AV:N/AC:L",
		"unsupported prefix": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"missing value":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A",
		"unknown metric":     "CVSS:3.1/XX:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"duplicate metric":   "CVSS:3.1/AV:N/AV:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"unknown value":      "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cvss3BaseScore(vector); err == nil {
				t.Fatalf("cvss3BaseScore(%q) error = nil, want error", vector)
			}
		})
	}
}

func TestRoundup30(t *testing.T) {
	for _, tc := range [][2]float64{
		{4.0, 4.0},
		{4.01, 4.1},
		{9.95, 10.0},
	} {
		if got := roundup30(tc[0]); got != tc[1] {
			t.Errorf("roundup30(%v) = %v, want %v", tc[0], got, tc[1])
		}
	}
}

func TestRoundup31(t *testing.T) {
	for _, tc := range [][2]float64{
		{4.0, 4.0},
		{4.01, 4.1},
		{9.99, 10.0},
		{0.0, 0.0},
	} {
		if got := roundup31(tc[0]); got != tc[1] {
			t.Errorf("roundup31(%v) = %v, want %v", tc[0], got, tc[1])
		}
	}
}
