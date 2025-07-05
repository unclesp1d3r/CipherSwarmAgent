package hashcat

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// Params represents the configuration parameters for running a hash cracking attack using Hashcat.
type Params struct {
	AttackMode                int64    `json:"attack_mode"`                  // Attack mode to use
	HashType                  int64    `json:"hash_type"`                    // Hash type to crack
	HashFile                  string   `json:"hash_file"`                    // Path to the file containing the hashes to crack
	Mask                      string   `json:"mask,omitempty"`               // Mask to use for mask attack
	MaskIncrement             bool     `json:"mask_increment,omitempty"`     // Whether to use mask increment
	MaskIncrementMin          int64    `json:"mask_increment_min"`           // Min mask length for increment
	MaskIncrementMax          int64    `json:"mask_increment_max"`           // Max mask length for increment
	MaskCustomCharsets        []string `json:"mask_custom_charsets"`         // Custom charsets for mask attack
	WordListFilename          string   `json:"wordlist_filename"`            // Wordlist to use for dictionary and hybrid attacks
	RuleListFilename          string   `json:"rules_filename"`               // Rule list to use for dictionary attack
	MaskListFilename          string   `json:"mask_list_filename"`           // Mask list to use for mask attack
	AdditionalArgs            []string `json:"additional_args"`              // Additional arguments to pass to hashcat
	OptimizedKernels          bool     `json:"optimized_kernels"`            // Whether to use optimized kernels
	SlowCandidates            bool     `json:"slow_candidates"`              // Whether to use slow candidates
	Skip                      int64    `json:"skip,omitempty"`               // Keyspace offset to start at
	Limit                     int64    `json:"limit,omitempty"`              // Maximum keyspace to process
	BackendDevices            string   `json:"backend_devices,omitempty"`    // Devices to use for the backend, comma-separated
	OpenCLDevices             string   `json:"opencl_devices,omitempty"`     // OpenCL devices to use, comma-separated
	EnableAdditionalHashTypes bool     `json:"enable_additional_hash_types"` // Whether to enable additional hash types when benchmarking
	RestoreFilePath           string   `json:"restore_file_path,omitempty"`  // Path to the restore file
}

// Validate checks the attack mode specified in the Params and calls corresponding validation methods.
// It returns an error if the validation fails or if an unsupported attack mode is provided.
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
		return fmt.Errorf("unsupported attack mode %d", params.AttackMode)
	}
}

// validateDictionaryAttack checks if the WordListFilename parameter is provided for a dictionary attack.
// It returns an error if the parameter is missing or blank.
func validateDictionaryAttack(params Params) error {
	if strings.TrimSpace(params.WordListFilename) == "" {
		return fmt.Errorf("expected 1 wordlist for dictionary attack (%d), but none given", attackModeDictionary)
	}

	return nil
}

// validateMaskAttack validates the parameters for a mask attack. It checks if either Mask or MaskListFilename is provided but not both.
func validateMaskAttack(params Params) error {
	if strings.TrimSpace(params.Mask) == "" && strings.TrimSpace(params.MaskListFilename) == "" {
		return fmt.Errorf("using mask attack (%d), but no mask was given", AttackModeMask)
	}
	if strings.TrimSpace(params.Mask) != "" && strings.TrimSpace(params.MaskListFilename) != "" {
		return fmt.Errorf("using mask attack (%d), but both mask and mask list were given", AttackModeMask)
	}

	return nil
}

// validateHybridAttack validates the parameters for a hybrid attack mode.
// It ensures that both a mask and a wordlist filename are provided.
func validateHybridAttack(params Params) error {
	if strings.TrimSpace(params.Mask) == "" {
		return fmt.Errorf("using hybrid attack (%d), but no mask was given", params.AttackMode)
	}
	if strings.TrimSpace(params.WordListFilename) == "" {
		return fmt.Errorf("expected 1 wordlist for hybrid attack (%d), but none given", params.AttackMode)
	}

	return nil
}

// maskArgs constructs command-line arguments for a mask attack configuration.
// Validates the number of custom charsets, then appends charset and increment options to args slice.
// Returns the constructed args slice or an error if validation fails.
func (params Params) maskArgs() ([]string, error) {
	const maxCharsets = 4
	if len(params.MaskCustomCharsets) > maxCharsets {
		return nil, fmt.Errorf("too many custom charsets supplied (%d), the max is %d", len(params.MaskCustomCharsets), maxCharsets)
	}

	args := make([]string, 0, len(params.MaskCustomCharsets)*2+6)

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

// toCmdArgs converts a Params object into a slice of command-line arguments for the Hashcat command.
// It includes several validation checks and conditional arguments based on the attack mode and presence of optional fields.
// Returns the generated arguments slice or an error if validation fails.
func (params Params) toCmdArgs(session, hashFile, outFile string) ([]string, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}

	args := make([]string, 0, 32)
	if params.AttackMode == AttackBenchmark {
		args = append(
			args,
			"--quiet",
			"--machine-readable",
			"--benchmark",
		)
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

	// For full attack mode, we have many more arguments to add
	args = append(
		args,
		"--quiet",
		"--session", "attack-"+session,
		"--outfile-format", "1,3,5",
		"--outfile", outFile,
		"--status",
		"--status-json",
		"--status-timer", strconv.FormatInt(int64(shared.State.StatusTimer), 10),
		"--potfile-disable",
		"--outfile-check-timer", strconv.FormatInt(int64(shared.State.StatusTimer), 10),
		"--outfile-check-dir", shared.State.ZapsPath,
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
		wordList := filepath.Join(shared.State.FilePath, filepath.Clean(params.WordListFilename))
		if _, err := os.Stat(wordList); os.IsNotExist(err) {
			err := fmt.Errorf("provided word list %q couldn't be opened on filesystem", wordList)

			return nil, err
		}
		params.WordListFilename = wordList // Update the path to the word list
	}

	if strings.TrimSpace(params.RuleListFilename) != "" {
		ruleList := filepath.Join(shared.State.FilePath, filepath.Clean(params.RuleListFilename))
		if _, err := os.Stat(ruleList); os.IsNotExist(err) {
			err := fmt.Errorf("provided rule list %q couldn't be opened on filesystem", ruleList)

			return nil, err
		}
		params.RuleListFilename = ruleList // Update the path to the rule list
	}

	// If there's a mask list, use it instead of the mask
	if strings.TrimSpace(params.MaskListFilename) != "" {
		maskList := filepath.Join(shared.State.FilePath, filepath.Clean(params.MaskListFilename))
		if _, err := os.Stat(maskList); os.IsNotExist(err) {
			err := fmt.Errorf("provided mask list %q couldn't be opened on filesystem", maskList)

			return nil, err
		}
		params.Mask = maskList // Update the path to the mask list
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

// toRestoreArgs constructs the command-line arguments needed to restore a Hashcat session using provided session details.
// Takes a session string as input and returns a slice of strings with the necessary restore arguments.
func (params Params) toRestoreArgs(session string) []string {
	return []string{
		"--session", "attack-" + session,
		"--restore-file-path", params.RestoreFilePath,
		"--restore",
	}
}
