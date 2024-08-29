package hashcat

import (
	"fmt"
	"path/filepath"

	"github.com/duke-git/lancet/convertor"
	"github.com/duke-git/lancet/fileutil"
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

// Validate checks if the parameters for the attack mode are valid.
// It returns an error if the parameters are invalid, or nil if they are valid.
func (params Params) Validate() error {
	switch params.AttackMode {
	case AttackModeDictionary:
		if strutil.IsBlank(params.WordListFilename) {
			return fmt.Errorf("expected 1 wordlist for dictionary attack (%d), but none given", AttackModeDictionary)
		}

	case AttackModeMask:
		if strutil.IsBlank(params.Mask) && strutil.IsBlank(params.MaskListFilename) {
			return fmt.Errorf("using mask attack (%d), but no mask was given", AttackModeMask)
		}

		if strutil.IsNotBlank(params.Mask) && strutil.IsNotBlank(params.MaskListFilename) {
			return fmt.Errorf("using mask attack (%d), but both mask and mask list were given", AttackModeMask)
		}

	case AttackModeHybridDM, AttackModeHybridMD:
		if params.Mask == "" {
			return fmt.Errorf("using hybrid attack (%d), but no mask was given", params.AttackMode)
		}
		if strutil.IsBlank(params.WordListFilename) {
			return fmt.Errorf("expected 1 wordlist for hybrid attack (%d), but none given", AttackModeDictionary)
		}
	case AttackBenchmark:
		// No additional validation needed
		return nil

	default:
		return fmt.Errorf("unsupported attack mode %d", params.AttackMode)
	}

	return nil
}

// maskArgs returns the command line arguments for the mask attack mode in Hashcat.
// It generates the arguments based on the provided Params struct.
// The function checks the number of custom charsets and returns an error if it exceeds the maximum allowed.
// It also handles the mask increment option and its corresponding minimum and maximum values.
// The returned arguments can be used directly in the command line when invoking Hashcat.
func (params Params) maskArgs() ([]string, error) {
	maxCharsets := 4
	if len(params.MaskCustomCharsets) > maxCharsets {
		return nil, fmt.Errorf("too many custom charsets supplied (%d), the max is %d", len(params.MaskCustomCharsets), maxCharsets)
	}

	var args []string

	for i, charset := range params.MaskCustomCharsets {
		// Hashcat accepts parameters --custom-charset1 to --custom-charset4
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

// toCmdArgs converts the Params struct into a slice of command-line arguments for the hashcat command.
// It takes the session name, hash file path, and output file path as input parameters.
// It returns the generated command-line arguments and any error encountered during the conversion.
func (params Params) toCmdArgs(session, hashFile string, outFile string) (args []string, err error) {
	if err = params.Validate(); err != nil {
		return
	}

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

		return // No need to for further arguments for benchmark mode
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
			err = fmt.Errorf("provided word list %q couldn't be opened on filesystem", wordList)
			return
		}
		params.WordListFilename = wordList // Update the path to the word list
	}

	if strutil.IsNotBlank(params.RuleListFilename) {
		ruleList := filepath.Join(shared.State.FilePath, filepath.Clean(params.RuleListFilename))
		if !fileutil.IsExist(ruleList) {
			err = fmt.Errorf("provided rule list %q couldn't be opened on filesystem", ruleList)
			return
		}
		params.RuleListFilename = ruleList // Update the path to the rule list
	}

	// If there's a mask list, use it instead of the mask
	if strutil.IsNotBlank(params.MaskListFilename) {
		maskList := filepath.Join(shared.State.FilePath, filepath.Clean(params.MaskListFilename))
		if !fileutil.IsExist(maskList) {
			err = fmt.Errorf("provided mask list %q couldn't be opened on filesystem", maskList)
			return
		}
		params.Mask = maskList // Update the path to the mask list
	}

	args = append(args, hashFile)

	switch params.AttackMode {
	case AttackModeDictionary:
		args = append(args, params.WordListFilename)

		if strutil.IsNotBlank(params.RuleListFilename) {
			args = append(args, "-r", params.RuleListFilename)
		}

	case AttackModeMask:
		args = append(args, params.Mask)

	case AttackModeHybridDM:
		args = append(args, params.WordListFilename, params.Mask)

	case AttackModeHybridMD:
		args = append(args, params.Mask, params.WordListFilename)
	}

	switch params.AttackMode {
	case AttackModeMask, AttackModeHybridDM, AttackModeHybridMD:
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

	return
}

func (params Params) toRestoreArgs(session string) (args []string, err error) {

	// We need a few arguments from standard attacks
	args = append(args, "--session", "attack-"+session)

	// Add the restore file path and the restore flag
	args = append(args, "--restore-file-path", params.RestoreFilePath)
	args = append(args, "--restore")

	return args, nil
}
