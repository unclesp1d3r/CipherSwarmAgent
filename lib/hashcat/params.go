package hashcat

import (
	"fmt"
	"path/filepath"

	"github.com/duke-git/lancet/convertor"
	"github.com/duke-git/lancet/fileutil"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

type Params struct {
	AttackMode uint8  `json:"attack_mode"` // Attack mode to use
	HashType   int32  `json:"hash_type"`   // Hash type to crack
	HashFile   string `json:"hash_file"`   // Path to the file containing the hashes to crack

	Mask               string   `json:"mask"`                 // Mask to use for mask attack
	MaskIncrement      bool     `json:"mask_increment"`       // Whether to use mask increment
	MaskIncrementMin   uint     `json:"mask_increment_min"`   // Min mask length for increment
	MaskIncrementMax   uint     `json:"mask_increment_max"`   // Max mask length for increment
	MaskShardedCharset string   `json:"mask_sharded_charset"` // Internal use: for sharding charsets
	MaskCustomCharsets []string `json:"mask_custom_charsets"` // Custom charsets for mask attack

	WordlistFilenames []string `json:"wordlist_filenames"` // Wordlists to use for dictionary and combinator attacks
	RulesFilenames    []string `json:"rules_filenames"`    // Rules to use for dictionary attack
	AdditionalArgs    []string `json:"additional_args"`    // Additional arguments to pass to hashcat
	OptimizedKernels  bool     `json:"optimized_kernels"`  // Whether to use optimized kernels
	SlowCandidates    bool     `json:"slow_candidates"`    // Whether to use slow candidates

	Skip  int64 `json:"skip"`  // Keyspace offset to start at
	Limit int64 `json:"limit"` // Maximum keyspace to process
}

// Validate checks if the parameters for the attack mode are valid.
// It returns an error if the parameters are invalid, or nil if they are valid.
func (params Params) Validate() error {
	switch params.AttackMode {
	case AttackModeDictionary:
		if len(params.WordlistFilenames) != 1 {
			return fmt.Errorf("expected 1 wordlist for dictionary attack (%d), but %d given", AttackModeDictionary,
				len(params.WordlistFilenames))
		}

	case AttackModeCombinator:
		if len(params.WordlistFilenames) != 2 {
			return fmt.Errorf("expected 2 wordlists for combinator attack (%d), but %d given", AttackModeCombinator,
				len(params.WordlistFilenames))
		}

	case AttackModeMask:
		if params.Mask == "" {
			return fmt.Errorf("using mask attack (%d), but no mask was given", AttackModeMask)
		}

	case AttackModeHybridDM, AttackModeHybridMD:
		if params.Mask == "" {
			return fmt.Errorf("using hybrid attack (%d), but no mask was given", params.AttackMode)
		}
		if len(params.WordlistFilenames) != 1 {
			return fmt.Errorf("using hybrid attack (%d), but %d wordlist were given", params.AttackMode,
				len(params.WordlistFilenames))
		}
	case AttackBenchmark:
		// No additional validation needed
		return nil

	default:
		return fmt.Errorf("unsupported attack mode %d", params.AttackMode)
	}

	return nil
}

func (params Params) maskArgs() ([]string, error) {
	maxCharsets := 4
	if params.MaskShardedCharset != "" {
		maxCharsets = 3
	}
	if len(params.MaskCustomCharsets) > maxCharsets {
		return nil, fmt.Errorf("too many custom charsets supplied (%d), the max is %d", len(params.MaskCustomCharsets), maxCharsets)
	}

	var args []string

	for i, charset := range params.MaskCustomCharsets {
		// Hashcat accepts parameters --custom-charset1 to --custom-charset4
		args = append(args, fmt.Sprintf("--custom-charset%d", i+1), charset)
	}

	// 4 is the "magic" charset used when sharding attacks
	if params.MaskShardedCharset != "" {
		args = append(args, "--custom-charset4", params.MaskShardedCharset)
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
		return
	}
	args = append(
		args,
		"--quiet",
		"--session", "sess-"+session,
		"--outfile-format", "1,3,5",
		"--outfile", outFile,
		"--status",
		"--status-json",
		"--status-timer", "3",
		"--potfile-disable",
		"-a", convertor.ToString(params.AttackMode),
		"-m", convertor.ToString(params.HashType),
	)

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

	wordlists := make([]string, len(params.WordlistFilenames))
	for i, list := range params.WordlistFilenames {
		wordlists[i] = filepath.Join(shared.SharedState.FilePath, filepath.Clean(list))
		if !fileutil.IsExist(wordlists[i]) {
			err = fmt.Errorf("provided wordlist %q couldn't be opened on filesystem", wordlists[i])
			return
		}
	}

	rules := make([]string, len(params.RulesFilenames))
	for i, rule := range params.RulesFilenames {
		rules[i] = filepath.Join(shared.SharedState.FilePath, filepath.Clean(rule))
		if !fileutil.IsExist(rules[i]) {
			err = fmt.Errorf("provided rules file %q couldn't be opened on filesystem", wordlists[i])
			return
		}
	}

	args = append(args, hashFile)

	switch params.AttackMode {
	case AttackModeDictionary:
		for _, rule := range rules {
			args = append(args, "-r", rule)
		}
		args = append(args, wordlists[0])

	case AttackModeCombinator:
		args = append(args, wordlists[0], wordlists[1])

	case AttackModeMask:
		args = append(args, params.Mask)

	case AttackModeHybridDM:
		args = append(args, wordlists[0], params.Mask)

	case AttackModeHybridMD:
		args = append(args, params.Mask, wordlists[0])
	}

	switch params.AttackMode {
	case AttackModeMask, AttackModeHybridDM, AttackModeHybridMD:
		maskArgs, err := params.maskArgs()
		if err != nil {
			return nil, err
		}
		args = append(args, maskArgs...)
	}

	return
}
