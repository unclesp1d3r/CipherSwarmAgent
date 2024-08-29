package hashcat

/*
MIT License

# Copyright (c) 2022-2023 Lachlan Davidson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/duke-git/lancet/fileutil"
	"github.com/duke-git/lancet/strutil"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/shared"
)

// Borrowed from PhatCrack project (github.com/lachlan2k/phatcrack) and modified

// NewHashcatSession creates a new Hashcat session with the specified ID and parameters.
// It returns a pointer to the created Session and an error, if any.
// The Session represents a running Hashcat session and provides channels for receiving cracked hashes,
// status updates, stderr messages, and stdout lines.
// The function takes an ID string and a Params struct as input.
// The ID is used to identify the session, and the Params struct contains the parameters for the Hashcat session.
// The function creates temporary files for storing the output and custom charsets, and sets the necessary permissions.
// It then constructs the command arguments based on the provided parameters and returns the initialized Session.
// If any error occurs during the creation of the session, an error is returned.
func NewHashcatSession(id string, params Params) (*Session, error) {
	var err error

	var outFile *os.File
	var shardedCharsetFile *os.File
	var charsetFiles []*os.File

	binaryPath := viper.GetString("hashcat_path")
	outFile, err = os.CreateTemp(shared.State.OutPath, id)
	if err != nil {
		return nil, fmt.Errorf("couldn't make a temp file to store output: %w", err)
	}
	err = outFile.Chmod(0o600)
	if err != nil {
		return nil, fmt.Errorf("couldn't set permissions on output file: %w", err)
	}

	charsetFiles = []*os.File{}
	for i, charset := range params.MaskCustomCharsets {
		if !strutil.IsBlank(charset) {
			charsetFile, err := os.CreateTemp(shared.State.OutPath, "charset*")
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
	}

	args, err := params.toCmdArgs(id, params.HashFile, outFile.Name())
	if err != nil {
		return nil, err
	}

	// Check for a restore file and generate the restore arguments if it exists
	// We'll override the command arguments if a restore file is found
	if !strutil.IsBlank(params.RestoreFilePath) {
		if fileutil.IsExist(params.RestoreFilePath) {
			args, err = params.toRestoreArgs(id)
			if err != nil {
				return nil, err
			}
		}
	}

	shared.ErrorLogger.Info("Hashcat command: ", args)

	return &Session{
		proc:               exec.Command(binaryPath, args...),
		hashFile:           params.HashFile,
		outFile:            outFile,
		charsetFiles:       charsetFiles,
		shardedCharsetFile: shardedCharsetFile,
		CrackedHashes:      make(chan Result, 5),
		StatusUpdates:      make(chan Status, 5),
		StderrMessages:     make(chan string, 5),
		StdoutLines:        make(chan string, 5),
		DoneChan:           make(chan error),
		SkipStatusUpdates:  params.AttackMode == AttackBenchmark,
		RestoreFilePath:    params.RestoreFilePath,
	}, nil
}
