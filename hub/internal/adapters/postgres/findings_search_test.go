package postgres

import "testing"

func TestEscapeHubFindingLikePattern(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"Plain Text":    "plain text",
		`100%_match`:    `100\%\_match`,
		`path\fragment`: `path\\fragment`,
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got := escapeHubFindingLikePattern(input); got != want {
				t.Fatalf("escapeHubFindingLikePattern(%q) = %q, want %q", input, got, want)
			}
		})
	}
}
