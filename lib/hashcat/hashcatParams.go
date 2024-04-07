package hashcat

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strconv"
)

type HashcatParams struct {
	AttackMode uint8  `json:"attack_mode"`
	HashType   uint   `json:"hash_type"`
	HashFile   string `json:"hash_file"`

	Mask               string   `json:"mask"`
	MaskIncrement      bool     `json:"mask_increment"`
	MaskIncrementMin   uint     `json:"mask_increment_min"`
	MaskIncrementMax   uint     `json:"mask_increment_max"`
	MaskShardedCharset string   `json:"mask_sharded_charset"` // Internal use: for sharding charsets
	MaskCustomCharsets []string `json:"mask_custom_charsets"`

	WordlistFilenames []string `json:"wordlist_filenames"`
	RulesFilenames    []string `json:"rules_filenames"`
	AdditionalArgs    []string `json:"additional_args"`
	OptimizedKernels  bool     `json:"optimized_kernels"`
	SlowCandidates    bool     `json:"slow_candidates"`

	Skip  int64 `json:"skip"`
	Limit int64 `json:"limit"`
}

func (params HashcatParams) Validate() error {
	switch params.AttackMode {
	case AttackModeDictionary:
		if len(params.WordlistFilenames) != 1 {
			return fmt.Errorf("expected 1 wordlist for dictionary attack (%d), but %d given", AttackModeDictionary, len(params.WordlistFilenames))
		}

	case AttackModeCombinator:
		if len(params.WordlistFilenames) != 2 {
			return fmt.Errorf("expected 2 wordlists for combinator attack (%d), but %d given", AttackModeCombinator, len(params.WordlistFilenames))
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
			return fmt.Errorf("using hybrid attack (%d), but %d wordlist were given", params.AttackMode, len(params.WordlistFilenames))
		}
	case AttackBenchmark:
		// No additional validation needed
		return nil

	default:
		return fmt.Errorf("unsupported attack mode %d", params.AttackMode)
	}

	return nil
}

func (params HashcatParams) maskArgs() ([]string, error) {
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
			args = append(args, "--increment-min", fmtUint(params.MaskIncrementMin))
		}

		if params.MaskIncrementMax > 0 {
			args = append(args, "--increment-max", fmtUint(params.MaskIncrementMax))
		}
	}

	return args, nil
}

func (params HashcatParams) ToCmdArgs(session, hashFile string, outFile string) (args []string, err error) {
	if err = params.Validate(); err != nil {
		return
	}

	listFilePath := viper.GetString("file_path")
	if params.AttackMode == AttackBenchmark {
		args = append(
			args,
			"--quiet",
			"--machine-readable",
			"--benchmark",
		)
		return
	} else {
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
			"-a", fmtUint(params.AttackMode),
			"-m", fmtUint(params.HashType),
		)
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

	wordlists := make([]string, len(params.WordlistFilenames))
	for i, list := range params.WordlistFilenames {
		wordlists[i] = filepath.Join(listFilePath, filepath.Clean(list))
		if _, err = os.Stat(wordlists[i]); err != nil {
			err = fmt.Errorf("provided wordlist %q couldn't be opened on filesystem", wordlists[i])
			return
		}
	}

	rules := make([]string, len(params.RulesFilenames))
	for i, rule := range params.RulesFilenames {
		rules[i] = filepath.Join(listFilePath, filepath.Clean(rule))
		if _, err = os.Stat(rules[i]); err != nil {
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
