package hashcat

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/lib"
	subprocess "github.com/unclesp1d3r/cipherswarmagent/lib/utils"
)

type Hashcat struct {
	BinaryFile string           `json:"binaryFile"`
	Algorithms map[int64]string `json:"algorithms"`
}

var (
	reMode           = regexp.MustCompile(`^Hash mode #(\d+)$`)
	reType           = regexp.MustCompile(`^\s*Name\.*:\s(.+)$`)
	DefaultSessionID = "hashcat"
)

func (h *Hashcat) LoadAlgorithms() {
	h.Algorithms = make(map[int64]string)

	var algorithmMode int64
	var algorithmName string

	args := []string{"--hash-info", "--quiet"}
	wdir, _ := filepath.Split(h.BinaryFile)
	cmd := subprocess.Subprocess{
		Status:  subprocess.SubprocessStatusNotStarted,
		WDir:    wdir,
		Program: h.BinaryFile,
		Args:    args,
		StdoutCallback: func(s string) {
			s = lib.CleanString(s)
			modeLine := reMode.FindStringSubmatch(s)
			if len(modeLine) == 2 {
				var err error
				algorithmMode, err = strconv.ParseInt(modeLine[1], 10, 64)
				if err != nil {
					return
				}
			} else {
				typeLine := reType.FindStringSubmatch(s)
				if len(typeLine) == 2 {
					algorithmName = typeLine[1]
					h.Algorithms[algorithmMode] = algorithmName
				}
			}
		},
		StderrCallback: func(s string) {
			s = lib.CleanString(s)
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", s)
		},
		PreProcess:  func() {},
		PostProcess: func() {},
	}
	cmd.Execute()
}

func (h *Hashcat) Devices() (devices string, err error) {
	workingDir, _ := filepath.Split(h.BinaryFile)

	c := exec.Command(h.BinaryFile, []string{"-I", "--quiet"}...)
	c.Dir = workingDir
	devicesBytes, err := c.CombinedOutput()
	if err != nil {
		return
	}

	devices = lib.CleanString(string(devicesBytes))

	return
}

// Benchmark runs a benchmark test for the specified hash mode using Hashcat.
// It returns the benchmark result as a string and any error encountered.
func (h *Hashcat) Benchmark(hashMode HashMode) (benchmark string, err error) {
	workingDir, _ := filepath.Split(h.BinaryFile)

	c := exec.Command(h.BinaryFile, []string{"-b", fmt.Sprintf("-m%d", hashMode), "--quiet"}...)
	c.Dir = workingDir
	benchmarkBytes, err := c.CombinedOutput()
	if err != nil {
		return
	}

	benchmark = lib.CleanString(string(benchmarkBytes))

	return
}

type AttackMode int64

const (
	AttackModeDictionary AttackMode = iota
	AttackModeCombinator
	_
	AttackModeMask
	_
	_
	AttackModeHybrid1
	AttackModeHybrid2
)

type HashMode int64

// Build constructs the command-line arguments for running Hashcat based on the provided HashcatArgs.
// It returns the constructed arguments as a slice of strings and an error if any required fields are missing.
func (ha *Args) Build() (args []string, err error) {
	if ha.Session == nil {
		ha.Session = &DefaultSessionID
	}

	if ha.Hash == nil {
		err = errors.New("missing hash")
		return
	}

	if ha.HashMode == nil {
		err = errors.New("missing hash mode (algorithm)")
		return
	}

	if ha.AttackMode == nil {
		err = errors.New("missing attack mode")
		return
	}

	if ha.StatusTimer == nil {
		err = errors.New("missing status timer")
		return
	}

	if ha.OutputFile == nil {
		err = errors.New("missing output file")
		return
	}

	if ha.OutputFormat == nil {
		err = errors.New("missing output format")
		return
	}

	args = append(args, fmt.Sprintf("--session=%s", *ha.Session))

	args = append(args, []string{"--status", "--status-json", fmt.Sprintf("--status-timer=%d", *ha.StatusTimer)}...)

	if ha.Quiet != nil && *ha.Quiet == true {
		args = append(args, "--quiet")
	}

	if ha.DisablePotFile != nil && *ha.DisablePotFile == true {
		args = append(args, "--potfile-disable")
	}

	if ha.DisableLogFile != nil && *ha.DisableLogFile == true {
		args = append(args, "--logfile-disable")
	}

	if ha.EnableOptimizedKernel != nil && *ha.EnableOptimizedKernel == true {
		args = append(args, "-O")
	}

	if ha.EnableSlowerCandidateGenerators != nil && *ha.EnableSlowerCandidateGenerators == true {
		args = append(args, "-S")
	}

	if ha.RemoveFoundHashes != nil && *ha.RemoveFoundHashes == true {
		args = append(args, "--remove")
	}

	if ha.IgnoreUsernames != nil && *ha.IgnoreUsernames == true {
		args = append(args, "--username")
	}

	if ha.DisableSelfTest != nil && *ha.DisableSelfTest == true {
		args = append(args, "--self-test-disable")
	}

	if ha.IgnoreWarnings != nil && *ha.IgnoreWarnings == true {
		args = append(args, "--force")
	}

	if ha.DisableMonitor != nil && *ha.DisableMonitor == true {
		args = append(args, "--hwmon-disable")
	} else if ha.TempAbort != nil {
		args = append(args, fmt.Sprintf("--hwmon-temp-abort=%d", *ha.TempAbort))
	}

	if ha.MarkovDisable != nil && *ha.MarkovDisable == true {
		args = append(args, "--markov-disable")
	}
	if ha.MarkovClassic != nil && *ha.MarkovClassic == true {
		args = append(args, "--markov-classic")
	}
	if ha.MarkovThreshold != nil {
		args = append(args, fmt.Sprintf("--markov-threshold=%d", *ha.MarkovThreshold))
	}

	if ha.WorkloadProfile != nil {
		args = append(args, fmt.Sprintf("-w%d", *ha.WorkloadProfile))
	}

	args = append(args, fmt.Sprintf("-m%d", *ha.HashMode))
	args = append(args, fmt.Sprintf("-a%d", *ha.AttackMode))
	args = append(args, *ha.Hash)

	if ha.DevicesIDs != nil {
		args = append(args, []string{"-d", strings.Trim(strings.Replace(fmt.Sprint(*ha.DevicesIDs), " ", ",", -1), "[]")}...)
	}

	if ha.DevicesTypes != nil {
		args = append(args, []string{"-D", strings.Trim(strings.Replace(fmt.Sprint(*ha.DevicesTypes), " ", ",", -1), "[]")}...)
	}

	if ha.ExtraArguments != nil && len(*ha.ExtraArguments) > 0 {
		args = append(args, *ha.ExtraArguments...)
	}

	args = append(args, []string{"-o", *ha.OutputFile}...)
	args = append(args, fmt.Sprintf("--outfile-format=%s", strings.Trim(strings.Replace(fmt.Sprint(*ha.OutputFormat), " ", ",", -1), "[]")))

	switch *ha.AttackMode {
	case AttackModeDictionary:
		if ha.Dictionaries == nil {
			err = errors.New("missing dictionaries")
			return
		}
		args = append(args, *ha.Dictionaries...)
		if ha.Rules != nil {
			for _, rule := range *ha.Rules {
				args = append(args, []string{"-r", rule}...)
			}
		}
	case AttackModeCombinator:
		if ha.LeftDictionary == nil {
			err = errors.New("missing left dictionary")
			return
		}
		if ha.RightDictionary == nil {
			err = errors.New("missing right dictionary")
			return
		}
		args = append(args, []string{*ha.LeftDictionary, *ha.RightDictionary}...)
		if ha.LeftRule != nil {
			args = append(args, []string{"-j", *ha.LeftRule}...)
		}
		if ha.RightRule != nil {
			args = append(args, []string{"-k", *ha.RightRule}...)
		}
	case AttackModeMask:
		if ha.MaskFile != nil {
			args = append(args, *ha.MaskFile)
		} else if ha.Mask != nil {
			if ha.CustomCharset1 != nil {
				args = append(args, []string{"-1", *ha.CustomCharset1}...)
			}
			if ha.CustomCharset2 != nil {
				args = append(args, []string{"-2", *ha.CustomCharset2}...)
			}
			if ha.CustomCharset3 != nil {
				args = append(args, []string{"-3", *ha.CustomCharset3}...)
			}
			if ha.CustomCharset4 != nil {
				args = append(args, []string{"-4", *ha.CustomCharset4}...)
			}
			args = append(args, *ha.Mask)
		} else {
			err = errors.New("missing mask")
			return
		}
		if ha.EnableMaskIncrementMode != nil && *ha.EnableMaskIncrementMode == true {
			if ha.MaskIncrementMin == nil || ha.MaskIncrementMax == nil {
				err = errors.New("missing mask increment min and/or max")
				return
			}
			if *ha.MaskIncrementMin > *ha.MaskIncrementMax {
				err = errors.New("mask increment min cannot be greater than mask increment max")
				return
			}
			args = append(args, []string{"-i", fmt.Sprintf("--increment-min=%d", *ha.MaskIncrementMin), fmt.Sprintf("--increment-max=%d", *ha.MaskIncrementMax)}...)
		}
	case AttackModeHybrid1:
		// Left (Dictionary)
		if ha.LeftDictionary == nil {
			err = errors.New("missing dictionary")
			return
		}
		args = append(args, *ha.LeftDictionary)
		if ha.LeftRule != nil {
			args = append(args, []string{"-j", *ha.LeftRule}...)
		}
		// Right (Mask)
		if ha.MaskFile != nil {
			args = append(args, *ha.MaskFile)
		} else if ha.Mask != nil {
			if ha.CustomCharset1 != nil {
				args = append(args, []string{"-1", *ha.CustomCharset1}...)
			}
			if ha.CustomCharset2 != nil {
				args = append(args, []string{"-2", *ha.CustomCharset2}...)
			}
			if ha.CustomCharset3 != nil {
				args = append(args, []string{"-3", *ha.CustomCharset3}...)
			}
			if ha.CustomCharset4 != nil {
				args = append(args, []string{"-4", *ha.CustomCharset4}...)
			}
			args = append(args, *ha.Mask)
		} else {
			err = errors.New("missing mask")
			return
		}
		if ha.EnableMaskIncrementMode != nil && *ha.EnableMaskIncrementMode == true {
			if ha.MaskIncrementMin == nil || ha.MaskIncrementMax == nil {
				err = errors.New("missing mask increment min and/or max")
				return
			}
			if *ha.MaskIncrementMin > *ha.MaskIncrementMax {
				err = errors.New("mask increment min cannot be greater than mask increment max")
				return
			}
			args = append(args, []string{"-i", fmt.Sprintf("--increment-min=%d", *ha.MaskIncrementMin), fmt.Sprintf("--increment-max=%d", *ha.MaskIncrementMax)}...)
		}
	case AttackModeHybrid2:
		// Left (Mask)
		if ha.MaskFile != nil {
			args = append(args, *ha.MaskFile)
		} else if ha.Mask != nil {
			if ha.CustomCharset1 != nil {
				args = append(args, []string{"-1", *ha.CustomCharset1}...)
			}
			if ha.CustomCharset2 != nil {
				args = append(args, []string{"-2", *ha.CustomCharset2}...)
			}
			if ha.CustomCharset3 != nil {
				args = append(args, []string{"-3", *ha.CustomCharset3}...)
			}
			if ha.CustomCharset4 != nil {
				args = append(args, []string{"-4", *ha.CustomCharset4}...)
			}
			args = append(args, *ha.Mask)
		} else {
			err = errors.New("missing mask")
			return
		}
		if ha.EnableMaskIncrementMode != nil && *ha.EnableMaskIncrementMode == true {
			if ha.MaskIncrementMin == nil || ha.MaskIncrementMax == nil {
				err = errors.New("missing mask increment min and/or max")
				return
			}
			if *ha.MaskIncrementMin > *ha.MaskIncrementMax {
				err = errors.New("mask increment min cannot be greater than mask increment max")
				return
			}
			args = append(args, []string{"-i", fmt.Sprintf("--increment-min=%d", *ha.MaskIncrementMin), fmt.Sprintf("--increment-max=%d", *ha.MaskIncrementMax)}...)
		}
		// Right (Dictionary)
		if ha.RightDictionary == nil {
			err = errors.New("missing dictionary")
			return
		}
		args = append(args, *ha.RightDictionary)
		if ha.RightRule != nil {
			args = append(args, []string{"-k", *ha.RightRule}...)
		}
	default:
		err = errors.New("unsupported attack mode")
		return
	}

	return
}
