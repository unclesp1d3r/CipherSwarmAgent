package hashcat

import (
	"fmt"
	"path/filepath"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/duke-git/lancet/v2/strutil"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

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

// Validate checks the Params struct for valid attack mode configurations.
// It validates the parameters based on the specified attack mode and returns
// an error if the attack mode is unsupported or if the parameters are invalid
// for the given attack mode.
//
// Supported attack modes:
// - attackModeDictionary: Validates dictionary attack parameters.
// - AttackModeMask: Validates mask attack parameters.
// - attackModeHybridDM, attackModeHybridMD: Validates hybrid attack parameters.
// - AttackBenchmark: No validation needed.
//
// Returns an error if the attack mode is unsupported or if validation fails.
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

func validateDictionaryAttack(params Params) error {
	if strutil.IsBlank(params.WordListFilename) {
		return fmt.Errorf("expected 1 wordlist for dictionary attack (%d), but none given", attackModeDictionary)
	}

	return nil
}

func validateMaskAttack(params Params) error {
	if strutil.IsBlank(params.Mask) && strutil.IsBlank(params.MaskListFilename) {
		return fmt.Errorf("using mask attack (%d), but no mask was given", AttackModeMask)
	}
	if strutil.IsNotBlank(params.Mask) && strutil.IsNotBlank(params.MaskListFilename) {
		return fmt.Errorf("using mask attack (%d), but both mask and mask list were given", AttackModeMask)
	}

	return nil
}

func validateHybridAttack(params Params) error {
	if strutil.IsBlank(params.Mask) {
		return fmt.Errorf("using hybrid attack (%d), but no mask was given", params.AttackMode)
	}
	if strutil.IsBlank(params.WordListFilename) {
		return fmt.Errorf("expected 1 wordlist for hybrid attack (%d), but none given", params.AttackMode)
	}

	return nil
}

// maskArgs returns the command line arguments for the mask attack mode in Hashcat.
// It generates the arguments based on the provided Params struct.
// The function checks the number of custom charsets and returns an error if it exceeds the maximum allowed.
// It also handles the mask increment option and its corresponding minimum and maximum values.
// The returned arguments can be used directly in the command line when invoking Hashcat.
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

// toCmdArgs generates the command-line arguments for running Hashcat based on the provided parameters.
// It validates the parameters and constructs the appropriate arguments for either benchmark mode or full attack mode.
//
// Parameters:
//   - session: A string representing the session name.
//   - hashFile: A string representing the path to the hash file.
//   - outFile: A string representing the path to the output file.
//
// Returns:
//   - A slice of strings containing the command-line arguments.
//   - An error if the parameters are invalid or if required files cannot be found.
//
// The function handles different attack modes and includes additional arguments based on the parameters provided.
// It ensures that required files such as word lists, rule lists, and mask lists exist before including them in the arguments.
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

// toRestoreArgs generates a slice of strings containing the arguments
// needed to restore a Hashcat session. It takes a session string as input
// and returns a slice of strings with the appropriate restore arguments.
//
// Parameters:
//
//	session (string): The session identifier to be used in the restore arguments.
//
// Returns:
//
//	[]string: A slice of strings containing the restore arguments for Hashcat.
func (params Params) toRestoreArgs(session string) []string {
	return []string{
		"--session", "attack-" + session,
		"--restore-file-path", params.RestoreFilePath,
		"--restore",
	}
}
