package hashcat

import (
	"fmt"
	"path/filepath"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// Params represents the configuration parameters for various attack modes in Hashcat.
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

// Validate checks the Params struct to ensure that the necessary parameters are provided based on the selected attack mode.
// It switches on the AttackMode field and calls the appropriate validation function for that mode.
// For unsupported attack modes, it returns an error indicating the invalid attack mode.
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

// validateDictionaryAttack checks if the necessary wordlist file is provided for a dictionary attack.
// It verifies if the WordListFilename field in Params is not blank.
// If the filename is blank, it returns an error indicating that the wordlist is missing.
func validateDictionaryAttack(params Params) error {
	if strutil.IsBlank(params.WordListFilename) {
		return fmt.Errorf("expected 1 wordlist for dictionary attack (%d), but none given", attackModeDictionary)
	}

	return nil
}

// validateMaskAttack checks the required parameters for a mask attack mode in Hashcat.
// It ensures either Mask or MaskListFilename is provided, but not both.
// Returns an error if validation fails.
func validateMaskAttack(params Params) error {
	if strutil.IsBlank(params.Mask) && strutil.IsBlank(params.MaskListFilename) {
		return fmt.Errorf("using mask attack (%d), but no mask was given", AttackModeMask)
	}
	if strutil.IsNotBlank(params.Mask) && strutil.IsNotBlank(params.MaskListFilename) {
		return fmt.Errorf("using mask attack (%d), but both mask and mask list were given", AttackModeMask)
	}

	return nil
}

// validateHybridAttack checks if the necessary parameters for a hybrid attack are provided.
// It validates the presence of both the mask and wordlist filename.
// Returns an error if any required parameter is missing.
func validateHybridAttack(params Params) error {
	if strutil.IsBlank(params.Mask) {
		return fmt.Errorf("using hybrid attack (%d), but no mask was given", params.AttackMode)
	}
	if strutil.IsBlank(params.WordListFilename) {
		return fmt.Errorf("expected 1 wordlist for hybrid attack (%d), but none given", params.AttackMode)
	}

	return nil
}

// maskArgs generates the command-line arguments for running a mask attack in Hashcat.
// It constructs the arguments for custom charsets and increments.
// Returns an error if too many custom charsets are supplied.
func (params Params) maskArgs() ([]string, error) {
	const maxCharsets = 4
	if len(params.MaskCustomCharsets) > maxCharsets {
		return nil, fmt.Errorf("too many custom charsets supplied (%d), the max is %d", len(params.MaskCustomCharsets), maxCharsets)
	}

	args := make([]string, 0, len(params.MaskCustomCharsets)*2+6)

	for i, charset := range params.MaskCustomCharsets {
		if strutil.IsNotBlank(charset) {
			args = append(args, fmt.Sprintf("--custom-charset%d", i+1), charset)
		}
	}

	if params.MaskIncrement {
		args = append(args, "--increment")
		if params.MaskIncrementMin > 0 {
			args = append(args, "--increment-min", convertor.ToString(params.MaskIncrementMin))
		}
		if params.MaskIncrementMax > 0 {
			args = append(args, "--increment-max", convertor.ToString(params.MaskIncrementMax))
		}
	}

	return args, nil
}

// toCmdArgs generates a slice of strings containing the command-line arguments for a Hashcat session.
// It performs validation of the parameters, constructs various arguments based on the attack mode, and
// updates certain file paths to ensure they exist on the filesystem before returning the final list of arguments.
// Returns an error if any required file path is invalid or if validation fails.
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
		if strutil.IsNotBlank(params.BackendDevices) {
			args = append(args, "--backend-devices", params.BackendDevices)
		}

		if strutil.IsNotBlank(params.OpenCLDevices) {
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
		"--status-timer", convertor.ToString(shared.State.StatusTimer),
		"--potfile-disable",
		"--outfile-check-timer", convertor.ToString(shared.State.StatusTimer),
		"--outfile-check-dir", shared.State.ZapsPath,
		"-a", convertor.ToString(params.AttackMode),
		"-m", convertor.ToString(params.HashType),
	)

	if strutil.IsNotBlank(params.RestoreFilePath) {
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
		args = append(args, "--skip", convertor.ToString(params.Skip))
	}

	if params.Limit > 0 {
		args = append(args, "--limit", convertor.ToString(params.Limit))
	}

	if strutil.IsNotBlank(params.WordListFilename) {
		wordList := filepath.Join(shared.State.FilePath, filepath.Clean(params.WordListFilename))
		if !fileutil.IsExist(wordList) {
			err := fmt.Errorf("provided word list %q couldn't be opened on filesystem", wordList)

			return nil, err
		}
		params.WordListFilename = wordList // Update the path to the word list
	}

	if strutil.IsNotBlank(params.RuleListFilename) {
		ruleList := filepath.Join(shared.State.FilePath, filepath.Clean(params.RuleListFilename))
		if !fileutil.IsExist(ruleList) {
			err := fmt.Errorf("provided rule list %q couldn't be opened on filesystem", ruleList)

			return nil, err
		}
		params.RuleListFilename = ruleList // Update the path to the rule list
	}

	// If there's a mask list, use it instead of the mask
	if strutil.IsNotBlank(params.MaskListFilename) {
		maskList := filepath.Join(shared.State.FilePath, filepath.Clean(params.MaskListFilename))
		if !fileutil.IsExist(maskList) {
			err := fmt.Errorf("provided mask list %q couldn't be opened on filesystem", maskList)

			return nil, err
		}
		params.Mask = maskList // Update the path to the mask list
	}

	args = append(args, hashFile)

	switch params.AttackMode {
	case attackModeDictionary:
		args = append(args, params.WordListFilename)

		if strutil.IsNotBlank(params.RuleListFilename) {
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

	if strutil.IsNotBlank(params.BackendDevices) {
		args = append(args, "--backend-devices", params.BackendDevices)
	}

	if strutil.IsNotBlank(params.OpenCLDevices) {
		args = append(args, "--opencl-device-types", params.OpenCLDevices)
	}

	return args, nil
}

// toRestoreArgs generates and returns the command-line arguments required to restore a Hashcat session.
func (params Params) toRestoreArgs(session string) []string {
	return []string{
		"--session", "attack-" + session,
		"--restore-file-path", params.RestoreFilePath,
		"--restore",
	}
}
