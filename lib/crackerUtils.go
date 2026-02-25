package lib

import (
	"context"

	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cserrors"
)

// setNativeHashcatPath sets the path for the native Hashcat binary if it is found in the system, otherwise logs and reports error.
func setNativeHashcatPath(ctx context.Context) error {
	agentstate.Logger.Debug("Using native Hashcat")

	binPath, err := cracker.FindHashcatBinary()
	if err != nil {
		agentstate.Logger.Error("Error finding hashcat binary: ", err)
		cserrors.SendAgentError(ctx, err.Error(), nil, api.SeverityCritical)

		return err
	}

	agentstate.Logger.Info("Found Hashcat binary", "path", binPath)
	agentstate.State.HashcatPath = binPath
	viper.Set("hashcat_path", binPath)

	if err := viper.WriteConfig(); err != nil {
		agentstate.Logger.Warn("Failed to persist hashcat path to config; path will be lost on restart",
			"error", err, "hashcat_path", binPath)
	}

	return nil
}
