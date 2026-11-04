package buildinfo

import "testing"

func TestVersion_PrefersStampedValue(t *testing.T) {
	for in, want := range map[string]string{"v0.10.2": "v0.10.2", "0.10.2": "v0.10.2"} {
		if got := Version(in); got != want {
			t.Errorf("Version(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVersion_FallsBackWithoutStamp(t *testing.T) {
	if got := Version(""); got == "" {
		t.Fatal("Version(\"\") is empty")
	}
}
