package lib

import (
	"errors"
	"strconv"

	"github.com/imroc/req/v3"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type AgentAuthenticationResult struct {
	// Authenticated represents the authentication status of the agent client.
	Authenticated bool `json:"authenticated"`
	AgentId       int  `json:"agent_id"`
}

type AgentConfiguration struct {
	// Configuration represents the configuration for the agent client.
	// It is a JSON field with the key "config".
	Configuration string `json:"config"`
	// ApiVersion represents the version of the API used by the agent client.
	ApiVersion int `json:"api_version"`
}

// AuthenticateAgent authenticates the agent with the CipherSwarm API.
// It sends a GET request to the "/authenticate" endpoint and checks the response.
// If the response is successful, it parses the response body into an AgentAuthenticationResult struct.
// If the agent is successfully authenticated, it logs a success message.
// If the agent fails to authenticate, it logs an error message and exits the program.
// If there is an error connecting to the CipherSwarm API, it logs an error message.
// Finally, it logs the response body for debugging purposes.
func AuthenticateAgent(client *req.Client) (int, error) {
	result := AgentAuthenticationResult{}
	resp, err := client.R().Get("/authenticate")
	if err != nil {
		logrus.Errorln("Error connecting to the CipherSwarm API", err)
		return 0, err
	}

	if resp.IsSuccessState() {
		err = resp.Into(&result)
		if err != nil {
			logrus.Fatal(err)
			return 0, err
		}

		if result.Authenticated {
			viper.Set("agent_id", result.AgentId)
			return result.AgentId, nil
		} else {
			logrus.Fatalln("Failed to authenticate with the CipherSwarm API")
			return 0, errors.New("failed to authenticate with the CipherSwarm API")
		}
	} else {
		logrus.Fatalf("bad response: %v", resp)
		return 0, resp.Err
	}
}

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API.
// It takes a req.Client as a parameter and returns an AgentConfiguration.
// If there is an error connecting to the API or if the response is not successful,
// it logs the error and returns an empty AgentConfiguration.
// If the response is successful, it logs the response body for debugging purposes.
func GetAgentConfiguration(client *req.Client) AgentConfiguration {
	rep, err := client.R().Get("/configuration")
	if err != nil {
		logrus.Errorln("Error connecting to the CipherSwarm API", err)
	}

	result := AgentConfiguration{}
	if rep.IsSuccessState() {
		logrus.Debugln(rep.String())
		err = rep.Into(&result)
		if err != nil {
			logrus.Fatal(err)
		}

	} else {
		logrus.Fatalf("bad response: %v", rep)
	}
	return result
}

// UpdateAgentMetadata updates the metadata of an agent.
// It takes a client object and an agent ID as parameters.
// It retrieves the host information and constructs an AgentMetadata object.
// The AgentMetadata object includes the agent's name, client signature, devices, and operating system.
// The agent metadata is then sent to the server using a PUT request.
// If there is an error retrieving the host information or updating the agent metadata, an error message is logged.
// The updated agent metadata is also logged for debugging purposes.
func UpdateAgentMetadata(client *req.Client, agentId int) {
	info, err := host.Info()
	if err != nil {
		logrus.Errorln("Error getting info info: ", err)
	}

	// client_signature represents the signature of the client, which includes the CipherSwarm Agent version, operating system, and kernel architecture.
	client_signature := "CipherSwarm Agent/" + AgentVersion + " " + info.OS + "/" + info.KernelArch

	agentMetadata := AgentMetadata{
		Name:            info.Hostname,
		ClientSignature: client_signature,
		Devices:         []string{"GPU0", "CPU0"},
	}

	switch info.OS {
	case "linux":
		agentMetadata.OperatingSystem = Linux
	case "windows":
		agentMetadata.OperatingSystem = Windows
	case "darwin":
		agentMetadata.OperatingSystem = MacOS
	default:
		agentMetadata.OperatingSystem = Other
	}

	_, err = client.R().SetBody(agentMetadata).Put("/agents/" + strconv.Itoa(agentId))
	if err != nil {
		logrus.Errorln("Error updating agent metadata: ", err)
	}
	logrus.Debugf("Agent metadata: %v", agentMetadata)
}

type AgentMetadata struct {
	Name            string   `json:"name"`
	ClientSignature string   `json:"client_signature"`
	Devices         []string `json:"devices"`
	OperatingSystem int      `json:"operating_system"`
}

var Configuration AgentConfiguration
