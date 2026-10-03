package options

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
)

func Test_flatten(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "single value",
			input:    []string{"docker"},
			expected: []string{"docker"},
		},
		{
			name:     "comma-separated values",
			input:    []string{"docker,registry"},
			expected: []string{"docker", "registry"},
		},
		{
			name:     "multiple entries with commas",
			input:    []string{"docker,registry", "podman"},
			expected: []string{"docker", "registry", "podman"}, // preserves order
		},
		{
			name:     "whitespace trimming",
			input:    []string{" docker , registry "},
			expected: []string{"docker", "registry"},
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flatten(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestGrype_OmitIgnoredMatchesConfig(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		env     map[string]string
		want    bool
		wantErr string
	}{
		{
			name: "default is off",
			want: false,
		},
		{
			name: "enabled from the config file",
			yaml: "omit-ignored-matches: true\n",
			want: true,
		},
		{
			name: "explicitly disabled in the config file",
			yaml: "omit-ignored-matches: false\n",
			want: false,
		},
		{
			name: "enabled from the environment",
			env:  map[string]string{"GRYPE_OMIT_IGNORED_MATCHES": "true"},
			want: true,
		},
		{
			name: "environment overrides the config file",
			yaml: "omit-ignored-matches: true\n",
			env:  map[string]string{"GRYPE_OMIT_IGNORED_MATCHES": "false"},
			want: false,
		},
		{
			name:    "cannot be combined with show-suppressed",
			yaml:    "omit-ignored-matches: true\nshow-suppressed: true\n",
			wantErr: "cannot be combined with --show-suppressed",
		},
		{
			name:    "cannot be combined with include-matcher-suppressions",
			env:     map[string]string{"GRYPE_OMIT_IGNORED_MATCHES": "true", "GRYPE_INCLUDE_MATCHER_SUPPRESSIONS": "true"},
			wantErr: "cannot be combined with include-matcher-suppressions",
		},
		{
			name: "show-suppressed alone is still allowed",
			yaml: "show-suppressed: true\n",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg := fangs.NewConfig("grype")
			// never pick up a config file from the developer's machine
			cfg.Finders = []fangs.Finder{func(fangs.Config) []string { return nil }}
			if tt.yaml != "" {
				path := filepath.Join(t.TempDir(), "grype.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.yaml), 0o600))
				cfg.Files = []string{path}
			}

			opts := DefaultGrype(clio.Identification{Name: "grype"})
			err := fangs.Load(cfg, &cobra.Command{}, opts)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, opts.OmitIgnoredMatches)
		})
	}
}
