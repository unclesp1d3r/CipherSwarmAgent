// Package hashcat provides parameter validation and command-line argument generation
// for hashcat operations. It handles configuration for various attack modes including
// dictionary, mask, and hybrid attacks, with comprehensive validation and error handling.
package hashcat

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

const (
	maxCharsets         = 4  // Maximum custom charsets allowed by hashcat
	defaultArgsCapacity = 32 // Default slice capacity for command arguments
	maskArgsCapacity    = 6  // Expected capacity for mask-specific arguments
)

var (
	// ErrUnsupportedAttackMode indicates an invalid or unsupported attack mode was specified.
	ErrUnsupportedAttackMode = errors.New("unsupported attack mode")
	// ErrDictionaryAttackWordlist indicates a dictionary attack is missing its required wordlist.
	ErrDictionaryAttackWordlist = errors.New("expected 1 wordlist for dictionary attack, but none given")
	// ErrMaskAttackNoMask indicates a mask attack is missing both mask and mask list.
	ErrMaskAttackNoMask = errors.New("using mask attack, but no mask was given")
	// ErrMaskAttackBothMaskAndList indicates both mask and mask list were provided (mutually exclusive).
	ErrMaskAttackBothMaskAndList = errors.New("using mask attack, but both mask and mask list were given")
	// ErrHybridAttackNoMask indicates a hybrid attack is missing its required mask.
	ErrHybridAttackNoMask = errors.New("using hybrid attack, but no mask was given")
	// ErrHybridAttackNoWordlist indicates a hybrid attack is missing its required wordlist.
	ErrHybridAttackNoWordlist = errors.New("expected 1 wordlist for hybrid attack, but none given")
	// ErrTooManyCustomCharsets indicates more custom charsets were provided than supported.
	ErrTooManyCustomCharsets = errors.New("too many custom charsets supplied")
	// ErrWordlistNotOpened indicates the specified wordlist file cannot be accessed.
	ErrWordlistNotOpened = errors.New("provided word list couldn't be opened on filesystem")
	// ErrRuleListNotOpened indicates the specified rule list file cannot be accessed.
	ErrRuleListNotOpened = errors.New("provided rule list couldn't be opened on filesystem")
	// ErrMaskListNotOpened indicates the specified mask list file cannot be accessed.
	ErrMaskListNotOpened = errors.New("provided mask list couldn't be opened on filesystem")
)

// Params represents the configuration parameters for a hashcat hash cracking attack.
// It contains all settings needed to configure and execute an attack including attack mode,
// hash type, input files, optimization flags, and device selection.
type Params struct {
	AttackMode                int64    `json:"attack_mode"`                  // Attack mode (0=dictionary, 3=mask, 6/7=hybrid, 9=benchmark)
	HashType                  int64    `json:"hash_type"`                    // Hashcat hash type code
	HashFile                  string   `json:"hash_file"`                    // Path to file containing target hashes
	Mask                      string   `json:"mask,omitempty"`               // Mask pattern for mask/hybrid attacks
	MaskIncrement             bool     `json:"mask_increment,omitempty"`     // Enable mask increment mode
	MaskIncrementMin          int64    `json:"mask_increment_min"`           // Minimum mask length for increment mode
	MaskIncrementMax          int64    `json:"mask_increment_max"`           // Maximum mask length for increment mode
	MaskCustomCharsets        []string `json:"mask_custom_charsets"`         // Custom character sets for mask attacks
	WordListFilename          string   `json:"wordlist_filename"`            // Path to wordlist file
	RuleListFilename          string   `json:"rules_filename"`               // Path to rules file for dictionary attacks
	MaskListFilename          string   `json:"mask_list_filename"`           // Path to mask list file
	AdditionalArgs            []string `json:"additional_args"`              // Extra command-line arguments
	OptimizedKernels          bool     `json:"optimized_kernels"`            // Use optimized kernels (-O flag)
	SlowCandidates            bool     `json:"slow_candidates"`              // Enable slow candidate generators (-S flag)
	Skip                      int64    `json:"skip,omitempty"`               // Skip N candidates from start
	Limit                     int64    `json:"limit,omitempty"`              // Stop after processing N candidates
	BackendDevices            string   `json:"backend_devices,omitempty"`    // Backend devices to use (comma-separated)
	OpenCLDevices             string   `json:"opencl_devices,omitempty"`     // OpenCL device types (comma-separated)
	EnableAdditionalHashTypes bool     `json:"enable_additional_hash_types"` // Enable all hash types in benchmark mode
	RestoreFilePath           string   `json:"restore_file_path,omitempty"`  // Path to restore file for session resumption
}

// Validate verifies that the Params configuration is valid for the specified attack mode.
// It delegates to attack-mode-specific validation functions and returns an error if
// the configuration is invalid or if an unsupported attack mode is specified.
func (params Params) Validate() error {
	switch params.AttackMode {
	case attackModeDictionary:
		return validateDictionaryAttack(params)
	case AttackModeMask:
		return validateMaskAttack(params)
	case attackModeHybridDM, attackModeHybridMD:
		return validateHybridAttack(params)
	case AttackBenchmark:
		return nil
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedAttackMode, params.AttackMode)
	}
}

// validateDictionaryAttack ensures a wordlist is specified for dictionary attacks.
func validateDictionaryAttack(params Params) error {
	if strings.TrimSpace(params.WordListFilename) == "" {
		return ErrDictionaryAttackWordlist
	}

	return nil
}

// validateMaskAttack ensures either a mask or mask list is provided, but not both.
func validateMaskAttack(params Params) error {
	if strings.TrimSpace(params.Mask) == "" && strings.TrimSpace(params.MaskListFilename) == "" {
		return ErrMaskAttackNoMask
	}

	if strings.TrimSpace(params.Mask) != "" && strings.TrimSpace(params.MaskListFilename) != "" {
		return ErrMaskAttackBothMaskAndList
	}

	return nil
}

// validateHybridAttack ensures both a mask and wordlist are provided for hybrid attacks.
func validateHybridAttack(params Params) error {
	if strings.TrimSpace(params.Mask) == "" {
		return ErrHybridAttackNoMask
	}

	if strings.TrimSpace(params.WordListFilename) == "" {
		return ErrHybridAttackNoWordlist
	}

	return nil
}

// maskArgs constructs command-line arguments for mask-based attacks.
// It validates the number of custom charsets and generates arguments for charset
// definitions and mask increment settings. Returns an error if validation fails.
func (params Params) maskArgs() ([]string, error) {
	if len(params.MaskCustomCharsets) > maxCharsets {
		return nil, fmt.Errorf(
			"%w (%d), the max is %d",
			ErrTooManyCustomCharsets,
			len(params.MaskCustomCharsets),
			maxCharsets,
		)
	}

	args := make([]string, 0, len(params.MaskCustomCharsets)*2+maskArgsCapacity)

	for i, charset := range params.MaskCustomCharsets {
		if strings.TrimSpace(charset) != "" {
			args = append(args, fmt.Sprintf("--custom-charset%d", i+1), charset)
		}
	}

	if params.MaskIncrement {
		args = append(args, "--increment")
		if params.MaskIncrementMin > 0 {
			args = append(args, "--increment-min", strconv.FormatInt(params.MaskIncrementMin, 10))
		}

		if params.MaskIncrementMax > 0 {
			args = append(args, "--increment-max", strconv.FormatInt(params.MaskIncrementMax, 10))
		}
	}

	return args, nil
}

// toCmdArgs converts Params into a complete hashcat command-line argument slice.
// It validates parameters, constructs base arguments, handles attack-mode-specific
// arguments, and validates file paths. Returns the argument slice or an error if
// validation fails or required files are missing.
func (params Params) toCmdArgs(session, hashFile, outFile string) ([]string, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}

	args := make([]string, 0, defaultArgsCapacity)
	if params.AttackMode == AttackBenchmark {
		args = append(
			args,
			"--quiet",
			"--machine-readable",
			"--benchmark",
		)

		args = append(args, params.AdditionalArgs...)

		if strings.TrimSpace(params.BackendDevices) != "" {
			args = append(args, "--backend-devices", params.BackendDevices)
		}

		if strings.TrimSpace(params.OpenCLDevices) != "" {
			args = append(args, "--opencl-device-types", params.OpenCLDevices)
		}

		if params.EnableAdditionalHashTypes {
			args = append(args, "--benchmark-all")
		}

		return args, nil
	}

	// Standard attack mode arguments
	args = append(
		args,
		"--quiet",
		"--session", "attack-"+session,
		"--outfile-format", "1,3,5",
		"--outfile", outFile,
		"--status",
		"--status-json",
		"--status-timer", strconv.FormatInt(int64(agentstate.State.StatusTimer), 10),
		"--potfile-disable",
		"--outfile-check-timer", strconv.FormatInt(int64(agentstate.State.StatusTimer), 10),
		"--outfile-check-dir", agentstate.State.ZapsPath,
		"-a", strconv.FormatInt(params.AttackMode, 10),
		"-m", strconv.FormatInt(params.HashType, 10),
	)

	if strings.TrimSpace(params.RestoreFilePath) != "" {
		args = append(args, "--restore-file-path", params.RestoreFilePath)
	}

	args = append(args, params.AdditionalArgs...)

	if params.OptimizedKernels {
		args = append(args, "-O")
	}

	if params.SlowCandidates {
		args = append(args, "-S")
	}

	if params.Skip > 0 {
		args = append(args, "--skip", strconv.FormatInt(params.Skip, 10))
	}

	if params.Limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(params.Limit, 10))
	}

	if strings.TrimSpace(params.WordListFilename) != "" {
		wordList, err := safePath(agentstate.State.FilePath, params.WordListFilename)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrWordlistNotOpened, err)
		}

		if _, err := os.Stat(wordList); os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrWordlistNotOpened, wordList)
		}

		params.WordListFilename = wordList
	}

	if strings.TrimSpace(params.RuleListFilename) != "" {
		ruleList, err := safePath(agentstate.State.FilePath, params.RuleListFilename)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRuleListNotOpened, err)
		}

		if _, err := os.Stat(ruleList); os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrRuleListNotOpened, ruleList)
		}

		params.RuleListFilename = ruleList
	}

	if strings.TrimSpace(params.MaskListFilename) != "" {
		maskList, err := safePath(agentstate.State.FilePath, params.MaskListFilename)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMaskListNotOpened, err)
		}

		if _, err := os.Stat(maskList); os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrMaskListNotOpened, maskList)
		}

		params.Mask = maskList
	}

	args = append(args, hashFile)

	switch params.AttackMode {
	case attackModeDictionary:
		args = append(args, params.WordListFilename)

		if strings.TrimSpace(params.RuleListFilename) != "" {
			args = append(args, "-r", params.RuleListFilename)
		}

	case AttackModeMask:
		args = append(args, params.Mask)

	case attackModeHybridDM:
		args = append(args, params.WordListFilename, params.Mask)

	case attackModeHybridMD:
		args = append(args, params.Mask, params.WordListFilename)
	}

	switch params.AttackMode {
	case AttackModeMask, attackModeHybridDM, attackModeHybridMD:
		maskArgs, err := params.maskArgs()
		if err != nil {
			return nil, err
		}

		args = append(args, maskArgs...)
	}

	if strings.TrimSpace(params.BackendDevices) != "" {
		args = append(args, "--backend-devices", params.BackendDevices)
	}

	if strings.TrimSpace(params.OpenCLDevices) != "" {
		args = append(args, "--opencl-device-types", params.OpenCLDevices)
	}

	return args, nil
}

// toRestoreArgs constructs arguments for restoring a hashcat session.
// It returns a minimal argument set for session restoration using the restore file.
func (params Params) toRestoreArgs(session string) []string {
	return []string{
		"--session", "attack-" + session,
		"--restore-file-path", params.RestoreFilePath,
		"--restore",
	}
}

// safePath joins base and filename, then verifies the result stays within base.
// This prevents path traversal attacks via filenames like "../../etc/passwd".
func safePath(base, filename string) (string, error) {
	joined := filepath.Join(base, filepath.Clean(filename))

	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolving base path: %w", err)
	}

	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("resolving joined path: %w", err)
	}

	prefix := absBase + string(filepath.Separator)
	if !strings.HasPrefix(absJoined, prefix) && absJoined != absBase {
		return "", fmt.Errorf("path %q escapes base directory %q", filename, base)
	}

	return absJoined, nil
}
