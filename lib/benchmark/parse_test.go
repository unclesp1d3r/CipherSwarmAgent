package benchmark

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/devices"
	"github.com/unclesp1d3r/cipherswarmagent/lib/display"
)

func TestParseHashInfoLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		line   string
		wantID string
		wantOK bool
	}{
		{name: "MD5", line: "0 | MD5 | Raw Hash", wantID: "0", wantOK: true},
		{name: "SHA1", line: "100 | SHA1 | Raw Hash", wantID: "100", wantOK: true},
		{name: "NTLM", line: "1000 | NTLM | Raw Hash", wantID: "1000", wantOK: true},
		{name: "leading spaces", line: "  500 | md5crypt | Raw Hash", wantID: "500", wantOK: true},
		{name: "empty line", line: "", wantID: "", wantOK: false},
		{name: "comment line", line: "# Hash types supported", wantID: "", wantOK: false},
		{name: "header line", line: "Hash-Mode | Hash-Name | Description", wantID: "", wantOK: false},
		{name: "separator line", line: "------+----------+---------", wantID: "", wantOK: false},
		{name: "no pipe", line: "12345", wantID: "", wantOK: false},
		{name: "text before pipe", line: "abc | something", wantID: "", wantOK: false},
		{name: "large hash type", line: "99999 | SomeHash | Category", wantID: "99999", wantOK: true},
		{name: "tab separated", line: "\t200 | bcrypt | Hashes", wantID: "200", wantOK: true},
		{name: "only pipe", line: "|", wantID: "", wantOK: false},
		{name: "zero padded", line: "0100 | SomeType | Cat", wantID: "0100", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			id, ok := parseHashInfoLine(tt.line)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantID, id)
			}
		})
	}
}

func TestBenchmarkLineRe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantMatch  bool
		wantGroups []string // [device, hashType, hashName, runtime, hashTime, speed]
	}{
		{
			name:       "basic decimal speed",
			input:      "1:0:MD5:100:50:1234567.89",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "MD5", "100", "50", "1234567.89"},
		},
		{
			name:       "scientific notation positive exponent",
			input:      "1:0:MD5:100:50:1.23e+09",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "MD5", "100", "50", "1.23e+09"},
		},
		{
			name:       "scientific notation negative exponent",
			input:      "2:1000:NTLM:200:100:1.23e-05",
			wantMatch:  true,
			wantGroups: []string{"2", "1000", "NTLM", "200", "100", "1.23e-05"},
		},
		{
			name:       "scientific notation uppercase E",
			input:      "1:0:MD5:100:50:1.23E+09",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "MD5", "100", "50", "1.23E+09"},
		},
		{
			name:       "scientific notation no sign",
			input:      "1:0:MD5:100:50:1e5",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "MD5", "100", "50", "1e5"},
		},
		{
			name:       "integer speed",
			input:      "1:0:MD5:100:50:1234567",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "MD5", "100", "50", "1234567"},
		},
		{
			name:       "zero speed",
			input:      "1:0:MD5:100:50:0",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "MD5", "100", "50", "0"},
		},
		{
			name:       "zero runtime and hash time",
			input:      "1:0:MD5:0:0:0",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "MD5", "0", "0", "0"},
		},
		{
			name:       "long hash name with hyphens",
			input:      "3:22000:WPA-PBKDF2-PMKID+EAPOL:500:250:45678.9",
			wantMatch:  true,
			wantGroups: []string{"3", "22000", "WPA-PBKDF2-PMKID+EAPOL", "500", "250", "45678.9"},
		},
		{
			name:       "hypothetical colon in hash name",
			input:      "1:0:sha256:20000:salt:100:50:1.23e+09",
			wantMatch:  true,
			wantGroups: []string{"1", "0", "sha256:20000:salt", "100", "50", "1.23e+09"},
		},
		{
			name:      "NaN speed rejected",
			input:     "1:0:MD5:100:50:NaN",
			wantMatch: false,
		},
		{
			name:      "Inf speed rejected",
			input:     "1:0:MD5:100:50:Inf",
			wantMatch: false,
		},
		{
			name:      "non-numeric device rejected",
			input:     "abc:0:MD5:100:50:100.0",
			wantMatch: false,
		},
		{
			name:      "non-numeric runtime rejected",
			input:     "1:0:MD5:abc:50:100.0",
			wantMatch: false,
		},
		{
			name:      "empty hash name rejected",
			input:     "1:0::100:50:100.0",
			wantMatch: false,
		},
		{
			name:      "leading whitespace rejected",
			input:     " 1:0:MD5:100:50:100.0",
			wantMatch: false,
		},
		{
			name:      "trailing whitespace rejected",
			input:     "1:0:MD5:100:50:100.0 ",
			wantMatch: false,
		},
		{
			name:      "empty line rejected",
			input:     "",
			wantMatch: false,
		},
		{
			name:      "too few fields rejected",
			input:     "1:0:MD5:100:50",
			wantMatch: false,
		},
		{
			name:      "garbage speed rejected",
			input:     "1:0:MD5:100:50:e.e.e",
			wantMatch: false,
		},
		{
			name:      "speed with only dot rejected",
			input:     "1:0:MD5:100:50:.",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matches := benchmarkLineRe.FindStringSubmatch(tt.input)
			if tt.wantMatch {
				require.NotNil(t, matches, "expected match for input: %s", tt.input)
				require.Len(t, matches, benchmarkMatchGroups)

				got := matches[1:] // strip full match
				assert.Equal(t, tt.wantGroups, got)
			} else {
				assert.Nil(t, matches, "expected no match for input: %s", tt.input)
			}
		})
	}
}

func TestHandleBenchmarkStdOutLine_ValidLine(t *testing.T) {
	t.Parallel()

	var results []display.BenchmarkResult

	handleBenchmarkStdOutLine("1:0:MD5:100:50:1234567.89", &results, nil)

	require.Len(t, results, 1)
	assert.Equal(t, "1", results[0].Device)
	assert.Equal(t, "0", results[0].HashType)
	assert.Equal(t, "100", results[0].RuntimeMs)
	assert.Equal(t, "50", results[0].HashTimeMs)
	assert.Equal(t, "1234567.89", results[0].SpeedHs)
	assert.Empty(t, results[0].DeviceName)
}

func TestHandleBenchmarkStdOutLine_DeviceNameEnrichment(t *testing.T) {
	t.Parallel()

	dm := devices.NewDeviceManagerForTest([]devices.Device{
		{ID: 1, Name: "NVIDIA GeForce RTX 3090", Type: "GPU", Backend: "OpenCL", IsAvailable: true},
	})

	var results []display.BenchmarkResult

	handleBenchmarkStdOutLine("1:0:MD5:100:50:1234567.89", &results, dm)

	require.Len(t, results, 1)
	assert.Equal(t, "NVIDIA GeForce RTX 3090", results[0].DeviceName)
}

func TestHandleBenchmarkStdOutLine_UnknownDevice(t *testing.T) {
	t.Parallel()

	dm := devices.NewDeviceManagerForTest([]devices.Device{
		{ID: 2, Name: "Other GPU", Type: "GPU", Backend: "CUDA", IsAvailable: true},
	})

	var results []display.BenchmarkResult

	handleBenchmarkStdOutLine("1:0:MD5:100:50:1234567.89", &results, dm)

	require.Len(t, results, 1)
	assert.Empty(t, results[0].DeviceName, "unknown device ID should not populate DeviceName")
}

func TestHandleBenchmarkStdOutLine_MalformedLine(t *testing.T) {
	t.Parallel()

	var results []display.BenchmarkResult

	handleBenchmarkStdOutLine("not a benchmark line", &results, nil)

	assert.Empty(t, results)
}

func TestHandleBenchmarkStdOutLine_ScientificNotation(t *testing.T) {
	t.Parallel()

	var results []display.BenchmarkResult

	handleBenchmarkStdOutLine("2:1000:NTLM:200:100:1.23e+09", &results, nil)

	require.Len(t, results, 1)
	assert.Equal(t, "1.23e+09", results[0].SpeedHs)
}
