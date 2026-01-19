package hashcat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// setupTestState sets up a minimal test state for hashcat tests.
func setupTestState(t *testing.T) func() {
	t.Helper()

	// Save original values
	originalStatusTimer := agentstate.State.StatusTimer
	originalFilePath := agentstate.State.FilePath
	originalZapsPath := agentstate.State.ZapsPath

	// Create temp directories for testing
	tempDir := t.TempDir()
	filesDir := filepath.Join(tempDir, "files")
	zapsDir := filepath.Join(tempDir, "zaps")

	require.NoError(t, os.MkdirAll(filesDir, 0o750))
	require.NoError(t, os.MkdirAll(zapsDir, 0o750))

	// Set test values
	agentstate.State.StatusTimer = 5
	agentstate.State.FilePath = filesDir
	agentstate.State.ZapsPath = zapsDir

	return func() {
		// Restore original values
		agentstate.State.StatusTimer = originalStatusTimer
		agentstate.State.FilePath = originalFilePath
		agentstate.State.ZapsPath = originalZapsPath
	}
}

// createTestFile creates a temporary file for testing.
func createTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)

	return path
}

func TestParams_Validate_DictionaryAttack(t *testing.T) {
	tests := []struct {
		name        string
		params      Params
		expectError error
	}{
		{
			name: "valid dictionary attack",
			params: Params{
				AttackMode:       attackModeDictionary,
				WordListFilename: "wordlist.txt",
			},
			expectError: nil,
		},
		{
			name: "dictionary attack without wordlist",
			params: Params{
				AttackMode:       attackModeDictionary,
				WordListFilename: "",
			},
			expectError: ErrDictionaryAttackWordlist,
		},
		{
			name: "dictionary attack with whitespace-only wordlist",
			params: Params{
				AttackMode:       attackModeDictionary,
				WordListFilename: "   ",
			},
			expectError: ErrDictionaryAttackWordlist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()

			if tt.expectError == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.expectError)
			}
		})
	}
}

func TestParams_Validate_MaskAttack(t *testing.T) {
	tests := []struct {
		name        string
		params      Params
		expectError error
	}{
		{
			name: "valid mask attack with mask",
			params: Params{
				AttackMode: AttackModeMask,
				Mask:       "?a?a?a?a",
			},
			expectError: nil,
		},
		{
			name: "valid mask attack with mask list",
			params: Params{
				AttackMode:       AttackModeMask,
				MaskListFilename: "masks.hcmask",
			},
			expectError: nil,
		},
		{
			name: "mask attack without mask or mask list",
			params: Params{
				AttackMode: AttackModeMask,
			},
			expectError: ErrMaskAttackNoMask,
		},
		{
			name: "mask attack with both mask and mask list",
			params: Params{
				AttackMode:       AttackModeMask,
				Mask:             "?a?a?a?a",
				MaskListFilename: "masks.hcmask",
			},
			expectError: ErrMaskAttackBothMaskAndList,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()

			if tt.expectError == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.expectError)
			}
		})
	}
}

func TestParams_Validate_HybridAttack(t *testing.T) {
	tests := []struct {
		name        string
		params      Params
		expectError error
	}{
		{
			name: "valid hybrid dictionary+mask attack",
			params: Params{
				AttackMode:       attackModeHybridDM,
				Mask:             "?d?d?d",
				WordListFilename: "wordlist.txt",
			},
			expectError: nil,
		},
		{
			name: "valid hybrid mask+dictionary attack",
			params: Params{
				AttackMode:       attackModeHybridMD,
				Mask:             "?d?d?d",
				WordListFilename: "wordlist.txt",
			},
			expectError: nil,
		},
		{
			name: "hybrid attack without mask",
			params: Params{
				AttackMode:       attackModeHybridDM,
				WordListFilename: "wordlist.txt",
			},
			expectError: ErrHybridAttackNoMask,
		},
		{
			name: "hybrid attack without wordlist",
			params: Params{
				AttackMode: attackModeHybridDM,
				Mask:       "?d?d?d",
			},
			expectError: ErrHybridAttackNoWordlist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()

			if tt.expectError == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.expectError)
			}
		})
	}
}

func TestParams_Validate_BenchmarkMode(t *testing.T) {
	params := Params{
		AttackMode: AttackBenchmark,
	}

	err := params.Validate()
	assert.NoError(t, err)
}

func TestParams_Validate_UnsupportedAttackMode(t *testing.T) {
	params := Params{
		AttackMode: 99, // Invalid attack mode
	}

	err := params.Validate()
	assert.ErrorIs(t, err, ErrUnsupportedAttackMode)
}

func TestParams_MaskArgs(t *testing.T) {
	tests := []struct {
		name        string
		params      Params
		expectArgs  []string
		expectError error
	}{
		{
			name:       "no mask options",
			params:     Params{},
			expectArgs: []string{},
		},
		{
			name: "single custom charset",
			params: Params{
				MaskCustomCharsets: []string{"abc123"},
			},
			expectArgs: []string{"--custom-charset1", "abc123"},
		},
		{
			name: "multiple custom charsets",
			params: Params{
				MaskCustomCharsets: []string{"abc", "123", "!@#", "xyz"},
			},
			expectArgs: []string{
				"--custom-charset1", "abc",
				"--custom-charset2", "123",
				"--custom-charset3", "!@#",
				"--custom-charset4", "xyz",
			},
		},
		{
			name: "skip empty charsets",
			params: Params{
				MaskCustomCharsets: []string{"abc", "", "  ", "xyz"},
			},
			expectArgs: []string{
				"--custom-charset1", "abc",
				"--custom-charset4", "xyz",
			},
		},
		{
			name: "too many charsets",
			params: Params{
				MaskCustomCharsets: []string{"a", "b", "c", "d", "e"},
			},
			expectError: ErrTooManyCustomCharsets,
		},
		{
			name: "increment mode",
			params: Params{
				MaskIncrement: true,
			},
			expectArgs: []string{"--increment"},
		},
		{
			name: "increment with min and max",
			params: Params{
				MaskIncrement:    true,
				MaskIncrementMin: 4,
				MaskIncrementMax: 8,
			},
			expectArgs: []string{
				"--increment",
				"--increment-min", "4",
				"--increment-max", "8",
			},
		},
		{
			name: "charsets with increment",
			params: Params{
				MaskCustomCharsets: []string{"abc"},
				MaskIncrement:      true,
				MaskIncrementMin:   1,
				MaskIncrementMax:   10,
			},
			expectArgs: []string{
				"--custom-charset1", "abc",
				"--increment",
				"--increment-min", "1",
				"--increment-max", "10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := tt.params.maskArgs()

			if tt.expectError != nil {
				assert.ErrorIs(t, err, tt.expectError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectArgs, args)
		})
	}
}

func TestParams_ToCmdArgs_Benchmark(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	tests := []struct {
		name       string
		params     Params
		expectArgs []string
	}{
		{
			name: "basic benchmark",
			params: Params{
				AttackMode: AttackBenchmark,
			},
			expectArgs: []string{
				"--quiet",
				"--machine-readable",
				"--benchmark",
			},
		},
		{
			name: "benchmark with backend devices",
			params: Params{
				AttackMode:     AttackBenchmark,
				BackendDevices: "1,2",
			},
			expectArgs: []string{
				"--quiet",
				"--machine-readable",
				"--benchmark",
				"--backend-devices", "1,2",
			},
		},
		{
			name: "benchmark with OpenCL devices",
			params: Params{
				AttackMode:    AttackBenchmark,
				OpenCLDevices: "1,2,3",
			},
			expectArgs: []string{
				"--quiet",
				"--machine-readable",
				"--benchmark",
				"--opencl-device-types", "1,2,3",
			},
		},
		{
			name: "benchmark all hash types",
			params: Params{
				AttackMode:                AttackBenchmark,
				EnableAdditionalHashTypes: true,
			},
			expectArgs: []string{
				"--quiet",
				"--machine-readable",
				"--benchmark",
				"--benchmark-all",
			},
		},
		{
			name: "benchmark with additional args",
			params: Params{
				AttackMode:     AttackBenchmark,
				AdditionalArgs: []string{"-m", "0"},
			},
			expectArgs: []string{
				"--quiet",
				"--machine-readable",
				"--benchmark",
				"-m", "0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := tt.params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

			require.NoError(t, err)
			assert.Equal(t, tt.expectArgs, args)
		})
	}
}

func TestParams_ToCmdArgs_Dictionary(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	// Create test wordlist
	wordlist := createTestFile(t, agentstate.State.FilePath, "wordlist.txt", "password\n123456\n")

	params := Params{
		AttackMode:       attackModeDictionary,
		HashType:         0, // MD5
		WordListFilename: "wordlist.txt",
	}

	args, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	require.NoError(t, err)
	assert.Contains(t, args, "--quiet")
	assert.Contains(t, args, "--session")
	assert.Contains(t, args, "attack-test-session")
	assert.Contains(t, args, "-a")
	assert.Contains(t, args, "0") // Dictionary mode
	assert.Contains(t, args, "-m")
	assert.Contains(t, args, wordlist)
}

func TestParams_ToCmdArgs_DictionaryWithRules(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	// Create test files
	createTestFile(t, agentstate.State.FilePath, "wordlist.txt", "password\n")
	createTestFile(t, agentstate.State.FilePath, "rules.rule", ":\n")

	params := Params{
		AttackMode:       attackModeDictionary,
		HashType:         0,
		WordListFilename: "wordlist.txt",
		RuleListFilename: "rules.rule",
	}

	args, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	require.NoError(t, err)
	assert.Contains(t, args, "-r")
}

func TestParams_ToCmdArgs_MissingWordlist(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	params := Params{
		AttackMode:       attackModeDictionary,
		HashType:         0,
		WordListFilename: "nonexistent.txt",
	}

	_, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	assert.ErrorIs(t, err, ErrWordlistNotOpened)
}

func TestParams_ToCmdArgs_MissingRulelist(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	// Create wordlist but not rule list
	createTestFile(t, agentstate.State.FilePath, "wordlist.txt", "password\n")

	params := Params{
		AttackMode:       attackModeDictionary,
		HashType:         0,
		WordListFilename: "wordlist.txt",
		RuleListFilename: "nonexistent.rule",
	}

	_, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	assert.ErrorIs(t, err, ErrRuleListNotOpened)
}

func TestParams_ToCmdArgs_MissingMasklist(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	params := Params{
		AttackMode:       AttackModeMask,
		HashType:         0,
		MaskListFilename: "nonexistent.hcmask",
	}

	_, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	assert.ErrorIs(t, err, ErrMaskListNotOpened)
}

func TestParams_ToCmdArgs_OptionalFlags(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	// Create test wordlist
	createTestFile(t, agentstate.State.FilePath, "wordlist.txt", "password\n")

	params := Params{
		AttackMode:       attackModeDictionary,
		HashType:         0,
		WordListFilename: "wordlist.txt",
		OptimizedKernels: true,
		SlowCandidates:   true,
		Skip:             100,
		Limit:            1000,
		RestoreFilePath:  "/tmp/restore.bin",
		BackendDevices:   "1,2",
		OpenCLDevices:    "1,2,3",
		AdditionalArgs:   []string{"--force"},
	}

	args, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	require.NoError(t, err)
	assert.Contains(t, args, "-O")
	assert.Contains(t, args, "-S")
	assert.Contains(t, args, "--skip")
	assert.Contains(t, args, "100")
	assert.Contains(t, args, "--limit")
	assert.Contains(t, args, "1000")
	assert.Contains(t, args, "--restore-file-path")
	assert.Contains(t, args, "/tmp/restore.bin")
	assert.Contains(t, args, "--backend-devices")
	assert.Contains(t, args, "1,2")
	assert.Contains(t, args, "--opencl-device-types")
	assert.Contains(t, args, "1,2,3")
	assert.Contains(t, args, "--force")
}

func TestParams_ToRestoreArgs(t *testing.T) {
	params := Params{
		RestoreFilePath: "/tmp/session.restore",
	}

	args := params.toRestoreArgs("my-session")

	expected := []string{
		"--session", "attack-my-session",
		"--restore-file-path", "/tmp/session.restore",
		"--restore",
	}

	assert.Equal(t, expected, args)
}

func TestParams_ToCmdArgs_MaskAttack(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	params := Params{
		AttackMode: AttackModeMask,
		HashType:   0,
		Mask:       "?a?a?a?a",
	}

	args, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	require.NoError(t, err)
	assert.Contains(t, args, "-a")
	assert.Contains(t, args, "3") // Mask mode
	assert.Contains(t, args, "?a?a?a?a")
}

func TestParams_ToCmdArgs_MaskListAttack(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	// Create test mask list
	createTestFile(t, agentstate.State.FilePath, "masks.hcmask", "?l?l?l?l\n?d?d?d?d\n")

	params := Params{
		AttackMode:       AttackModeMask,
		HashType:         0,
		MaskListFilename: "masks.hcmask",
	}

	args, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	require.NoError(t, err)
	// Mask should be set to the mask list path
	assert.Contains(t, args, filepath.Join(agentstate.State.FilePath, "masks.hcmask"))
}

func TestParams_ToCmdArgs_HybridDMAttack(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	// Create test wordlist
	createTestFile(t, agentstate.State.FilePath, "wordlist.txt", "password\n")

	params := Params{
		AttackMode:       attackModeHybridDM,
		HashType:         0,
		WordListFilename: "wordlist.txt",
		Mask:             "?d?d?d",
	}

	args, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	require.NoError(t, err)
	assert.Contains(t, args, "-a")
	assert.Contains(t, args, "6") // Hybrid DM mode
	assert.Contains(t, args, "?d?d?d")
}

func TestParams_ToCmdArgs_HybridMDAttack(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	// Create test wordlist
	createTestFile(t, agentstate.State.FilePath, "wordlist.txt", "password\n")

	params := Params{
		AttackMode:       attackModeHybridMD,
		HashType:         0,
		WordListFilename: "wordlist.txt",
		Mask:             "?d?d?d",
	}

	args, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	require.NoError(t, err)
	assert.Contains(t, args, "-a")
	assert.Contains(t, args, "7") // Hybrid MD mode
}

func TestParams_ToCmdArgs_ValidationFails(t *testing.T) {
	params := Params{
		AttackMode: 99, // Invalid
	}

	_, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	assert.ErrorIs(t, err, ErrUnsupportedAttackMode)
}

func TestParams_ToCmdArgs_MaskArgsError(t *testing.T) {
	cleanup := setupTestState(t)
	defer cleanup()

	params := Params{
		AttackMode:         AttackModeMask,
		HashType:           0,
		Mask:               "?a?a?a?a",
		MaskCustomCharsets: []string{"a", "b", "c", "d", "e"}, // Too many
	}

	_, err := params.toCmdArgs("test-session", "/tmp/hashes.txt", "/tmp/out.txt")

	assert.ErrorIs(t, err, ErrTooManyCustomCharsets)
}
