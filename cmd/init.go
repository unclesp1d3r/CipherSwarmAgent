/*
Copyright © 2024 UncleSp1d3r <unclespider@protonmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/manifoldco/promptui"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// initCmd represents the Init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the agent",
	Long:  "Initialize the agent.\nThis command should be run only once, unless you want to reset the agent configuration.",
	Run:   initializePrompts(),
}

// initializePrompts is a function that returns a function to be used as a Cobra command's RunE function.
// This function prompts the user for a token, URL, and writes the configuration to a file.
// If any error occurs during the prompts or writing the configuration, the function returns early.
func initializePrompts() func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		err := promptForToken()
		if err != nil {
			return
		}

		err = promptForUrl()
		if err != nil {
			return
		}

		err = viper.WriteConfig()
		if err != nil {
			return
		}
	}
}

// promptForUrl prompts the user to enter the CipherSwarm API URL and validates it.
// It sets the entered URL in the configuration using viper.
func promptForUrl() error {
	urlPrompt := promptui.Prompt{
		Label: "Enter the CipherSwarm API URL",
		Validate: func(input string) error {
			if len(input) > 0 {
				_, err := url.Parse(input)
				if err != nil {
					return err
				}
				return nil
			}
			return errors.New("invalid URL")
		},
	}

	apiUrl, err := urlPrompt.Run()
	if err != nil {
		fmt.Println(err)
		return err
	}
	viper.Set("api_url", apiUrl)
	return nil
}

// promptForToken prompts the user to enter the CipherSwarm API Token and stores it in the configuration.
// It returns an error if the entered token is invalid.
func promptForToken() error {
	tokenPrompt := promptui.Prompt{
		Label: "Enter the CipherSwarm API Token",
		Validate: func(input string) error {
			if len(input) == 24 {
				return nil
			}
			return errors.New("invalid API token")
		},
	}
	token, err := tokenPrompt.Run()
	if err != nil {
		log.Errorf("Prompt failed %v\n", err)
		return err
	}
	viper.Set("api_token", token)
	return nil
}

// init is a function that is automatically called before the main function.
// It adds the initCmd command to the rootCmd command.
func init() {
	rootCmd.AddCommand(initCmd)
}
