package core

import (
	"strings"
	"testing"
)

func TestResolveTermFXKeyTypos(t *testing.T) {
	cases := map[string]string{
		"title.spiiner": "title.spinner",
		"title.spiner":  "title.spinner",
		"title.tim":     "title.time",
		"title.time":    "title.time",
		"user.name":     "user.name",
	}
	for in, want := range cases {
		got := resolveTermFXKey(strings.ToLower(in))
		if got != want {
			t.Errorf("resolveTermFXKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderTermFXTitlePlaceholders(t *testing.T) {
	ctx := map[string]string{
		"title.spinner": "|",
		"title.time":    "12:34:56",
		"user.username": "alice",
	}
	s := RenderTermFX("<<$title.spiiner>> <<$title.time>> $title.time {title.time} <<$USER.USERNAME>>", ctx)
	if strings.Contains(s, "<<$") || strings.Contains(s, "title.spiiner") {
		t.Errorf("expected all placeholders expanded, got: %q", s)
	}
	if !strings.Contains(s, "|") || !strings.Contains(s, "12:34:56") || !strings.Contains(s, "alice") {
		t.Errorf("missing values: %q", s)
	}
}

func TestRenderTermFXInjectsTitleKeysWhenMissing(t *testing.T) {
	ctx := map[string]string{"user.username": "bob"}
	out := RenderTermFX("<<$title.spinner>>@<<$title.time>>@<<$title.fakebots>>", ctx)
	out = strings.ReplaceAll(out, "\r", "")
	out = strings.ReplaceAll(out, "\n", "")
	if strings.Contains(out, "<<$") {
		t.Fatalf("title keys should be auto-filled: %q", out)
	}
	parts := strings.Split(out, "@")
	// Panels: title.spinner / title.fakebots stay empty (title-bar only).
	if len(parts) != 3 || parts[0] != "" || parts[1] == "" || parts[2] != "" {
		t.Fatalf("expected empty@time@empty, got %q parts=%v", out, parts)
	}
}

func TestParseSpinnerFrames(t *testing.T) {
	t.Run("multiline", func(t *testing.T) {
		got := ParseSpinnerFrames("I\nIS\nISIS<3\n")
		want := []string{"I", "IS", "ISIS<3"}
		if len(got) != len(want) {
			t.Fatalf("got %v want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("frame %d: got %q want %q", i, got[i], want[i])
			}
		}
	})
	t.Run("singleLineFields", func(t *testing.T) {
		got := ParseSpinnerFrames("I IS ISI ISIS")
		if len(got) != 4 || got[3] != "ISIS" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("emptyUsesDefault", func(t *testing.T) {
		got := ParseSpinnerFrames("")
		def := DefaultSpinnerFrames()
		if len(got) != len(def) {
			t.Fatalf("got %v", got)
		}
	})
}
