package hashcat

// Borrowed from PhatCrack, a password cracking tool
import (
	"fmt"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/viper"
)

type uintIf interface {
	uint | uint8 | uint16 | uint32 | uint64
}

func fmtUint[T uintIf](x T) string {
	return strconv.FormatUint(uint64(x), 10)
}

func NewHashcatSession(id string, params Params) (*Session, error) {
	var err error

	var hashFile *os.File
	var outFile *os.File
	var shardedCharsetFile *os.File
	var charsetFiles []*os.File

	defer func() {
		if err == nil {
			return
		}
		// We returned because of an error, clean up temp files
		if hashFile != nil {
			os.Remove(hashFile.Name())
		}
		if outFile != nil {
			os.Remove(outFile.Name())
		}
		if shardedCharsetFile != nil {
			os.Remove(shardedCharsetFile.Name())
		}
		for _, f := range charsetFiles {
			if f != nil {
				os.Remove(f.Name())
			}
		}
	}()

	binaryPath := viper.GetString("hashcat_path")
	outFile, err = os.CreateTemp(shared.SharedState.OutPath, id)
	if err != nil {
		return nil, fmt.Errorf("couldn't make a temp file to store output: %w", err)
	}
	err = outFile.Chmod(0600)
	if err != nil {
		return nil, fmt.Errorf("couldn't set permissions on output file: %w", err)
	}

	charsetFiles = []*os.File{}
	for i, charset := range params.MaskCustomCharsets {
		charsetFile, err := os.CreateTemp(shared.SharedState.OutPath, "charset*")
		if err != nil {
			return nil, fmt.Errorf("couldn't make a temp file to store charset")
		}
		_, err = charsetFile.Write([]byte(charset))
		if err != nil {
			return nil, err
		}

		params.MaskCustomCharsets[i] = charsetFile.Name()
		charsetFiles = append(charsetFiles, charsetFile)
	}

	if params.MaskShardedCharset != "" {
		shardedCharsetFile, err = os.CreateTemp(shared.SharedState.OutPath, "charset*")
		if err != nil {
			return nil, fmt.Errorf("couldn't make a temp file to store charset")
		}
		err = outFile.Chmod(0600)
		if err != nil {
			return nil, err
		}

		_, err = shardedCharsetFile.Write([]byte(params.MaskShardedCharset))
		if err != nil {
			return nil, err
		}

		params.MaskShardedCharset = shardedCharsetFile.Name()
	}

	args, err := params.toCmdArgs(id, params.HashFile, outFile.Name())
	if err != nil {
		return nil, err
	}

	return &Session{
		proc:               exec.Command(binaryPath, args...),
		hashFile:           hashFile,
		outFile:            outFile,
		charsetFiles:       charsetFiles,
		shardedCharsetFile: shardedCharsetFile,
		CrackedHashes:      make(chan Result, 5),
		StatusUpdates:      make(chan Status, 5),
		StderrMessages:     make(chan string, 5),
		StdoutLines:        make(chan string, 5),
		DoneChan:           make(chan error),
		SkipStatusUpdates:  params.AttackMode == AttackBenchmark,
	}, nil
}
