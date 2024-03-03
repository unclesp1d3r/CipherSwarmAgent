package lib

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func UpdateClientConfig() {
	// These settings are mostly just placeholders for now
	viper.Set("api_version", Configuration.ApiVersion)
	viper.Set("agent_hashcat_parameters", Configuration.Configuration)
	err := viper.WriteConfig()
	if err != nil {
		logrus.Errorln("Error writing config file: ", err)
	}
}
