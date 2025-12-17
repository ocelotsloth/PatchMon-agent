package packages

import (
	"testing"

	"patchmon-agent/pkg/models"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPacmanManager_parseInstalledPackages(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	manager := NewPacmanManager(logger)

	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name: "valid single package",
			input: `vim 9.1.0123-1
`,
			expected: map[string]string{
				"vim": "9.1.0123-1",
			},
		},
		{
			name: "multiple packages",
			input: `vim 9.1.0123-1
glibc 2.39-3
bash 5.2.037-1
`,
			expected: map[string]string{
				"vim":   "9.1.0123-1",
				"glibc": "2.39-3",
				"bash":  "5.2.037-1",
			},
		},
		{
			name:     "empty input",
			input:    "",
			expected: map[string]string{},
		},
		{
			name: "ignores malformed lines",
			input: `vim 9.1.0123-1
this-is-not-valid
two  spaces  here
okpkg 1.0.0
`,
			expected: map[string]string{
				"vim":   "9.1.0123-1",
				"okpkg": "1.0.0",
			},
		},
		{
			name: "whitespace-only line is ignored",
			input: `vim 9.1.0123-1

okpkg 1.0.0
`,
			expected: map[string]string{
				"vim":   "9.1.0123-1",
				"okpkg": "1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.parseInstalledPackages(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPacmanManager_parseCheckUpdate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	manager := NewPacmanManager(logger)

	tests := []struct {
		name     string
		input    string
		expected []models.Package
	}{
		{
			name:  "standard update",
			input: `vim 9.1.0123-1 -> 9.1.0456-1`,
			expected: []models.Package{
				{
					Name:             "vim",
					CurrentVersion:   "9.1.0123-1",
					AvailableVersion: "9.1.0456-1",
					NeedsUpdate:      true,
					IsSecurityUpdate: false,
				},
			},
		},
		{
			name: "multiple updates",
			input: `vim 9.1.0123-1 -> 9.1.0456-1
glibc 2.39-3 -> 2.40-1
bash 5.2.037-1 -> 5.2.040-1
`,
			expected: []models.Package{
				{
					Name:             "vim",
					CurrentVersion:   "9.1.0123-1",
					AvailableVersion: "9.1.0456-1",
					NeedsUpdate:      true,
					IsSecurityUpdate: false,
				},
				{
					Name:             "glibc",
					CurrentVersion:   "2.39-3",
					AvailableVersion: "2.40-1",
					NeedsUpdate:      true,
					IsSecurityUpdate: false,
				},
				{
					Name:             "bash",
					CurrentVersion:   "5.2.037-1",
					AvailableVersion: "5.2.040-1",
					NeedsUpdate:      true,
					IsSecurityUpdate: false,
				},
			},
		},
		{
			name:     "empty input",
			input:    "",
			expected: []models.Package{},
		},
		{
			name: "ignores malformed lines",
			input: `vim 9.1.0123-1 -> 9.1.0456-1
this is not checkupdates output
pkg 1.0.0 -> 2.0.0 extra-field
okpkg 1 -> 2
`,
			expected: []models.Package{
				{
					Name:             "vim",
					CurrentVersion:   "9.1.0123-1",
					AvailableVersion: "9.1.0456-1",
					NeedsUpdate:      true,
					IsSecurityUpdate: false,
				},
				{
					Name:             "okpkg",
					CurrentVersion:   "1",
					AvailableVersion: "2",
					NeedsUpdate:      true,
					IsSecurityUpdate: false,
				},
			},
		},
		{
			name: "requires exact arrow formatting with spaces",
			input: `vim 9.1.0123-1->9.1.0456-1
vim 9.1.0123-1 -> 9.1.0456-1
`,
			expected: []models.Package{
				{
					Name:             "vim",
					CurrentVersion:   "9.1.0123-1",
					AvailableVersion: "9.1.0456-1",
					NeedsUpdate:      true,
					IsSecurityUpdate: false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.parseCheckUpdate(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPacmanManager_getUpgradablePackages_missingCheckupdates(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	manager := NewPacmanManager(logger)

	// Override lookPath to simulate missing checkupdates
	origLookPath := lookPath
	lookPath = func(file string) (string, error) {
		return "", assert.AnError
	}
	defer func() { lookPath = origLookPath }()

	pkgs, err := manager.getUpgradablePackages()
	assert.Error(t, err)
	assert.Nil(t, pkgs)
}
