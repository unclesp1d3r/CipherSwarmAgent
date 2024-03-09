package lib

import (
	"errors"
	"strconv"

	"github.com/charmbracelet/log"
	"github.com/imroc/req/v3"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/spf13/viper"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"

	"time"
)

var (
	// AgentPlatform represents the platform on which the agent is running.
	AgentPlatform = ""
	// logger is a logger instance used for logging in the agentClient package.
	logger log.Logger = *Logger
)

type AgentAuthenticationResult struct {
	// Authenticated represents the authentication status of the agent client.
	Authenticated bool `json:"authenticated"`
	// AgentId represents the unique identifier of the agent.
	AgentId int `json:"agent_id"`
}

type AgentConfiguration struct {
	Config struct {
		// UseNativeHashcat specifies whether to use the native Hashcat implementation.
		// If set to true, the agent will use the native Hashcat implementation.
		// If set to false, the agent will use a different implementation.
		UseNativeHashcat bool `json:"use_native_hashcat" yaml:"use_native_hashcat"`
	} `json:"config" yaml:"config"`
	// ApiVersion represents the version of the API used by the agent client.
	// It is specified as an integer and is used for JSON and YAML serialization.
	ApiVersion int `json:"api_version" yaml:"api_version"`
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
		logger.Error("Error connecting to the CipherSwarm API", err)
		return 0, err
	}

	if resp.IsSuccessState() {
		err = resp.Into(&result)
		if err != nil {
			logger.Fatal(err)
			return 0, err
		}

		if result.Authenticated {
			viper.Set("agent_id", result.AgentId)
			return result.AgentId, nil
		} else {
			return 0, errors.New("failed to authenticate with the CipherSwarm API")
		}
	} else {
		logger.Error("bad response: %v", resp)
		return 0, resp.Err
	}
}

// GetAgentConfiguration retrieves the agent configuration from the CipherSwarm API.
// It takes a req.Client as a parameter and returns an AgentConfiguration.
// If there is an error connecting to the API or if the response is not successful,
// it logs the error and returns an empty AgentConfiguration.
// If the response is successful, it logs the response body for debugging purposes.
func GetAgentConfiguration(client *req.Client) (AgentConfiguration, error) {
	rep, err := client.R().Get("/configuration")
	if err != nil {
		return AgentConfiguration{}, err
	}

	result := AgentConfiguration{}
	if rep.IsSuccessState() {
		logger.Debug(rep.String())
		err = rep.Into(&result)
		if err != nil {
			return AgentConfiguration{}, err
		}

	} else {
		return AgentConfiguration{}, errors.New("bad response: " + rep.String())
	}
	return result, nil
}

// UpdateAgentMetadata updates the metadata of an agent.
// It takes a client object and an agent ID as parameters.
// It retrieves the host information and constructs an AgentMetadata object.
// The AgentMetadata object includes the agent's name, client signature, devices, and operating system.
// The agent metadata is then sent to the server using a PUT request.
// If there is an error retrieving the host information or updating the agent metadata, an error message is logged.
// The updated agent metadata is also logged for debugging purposes.
func UpdateAgentMetadata(client *req.Client, agentId int) {
	logger.Info("Updating agent metadata with the CipherSwarm API")
	info, err := host.Info()
	if err != nil {
		logger.Error("Error getting info info: ", err)
	}

	// client_signature represents the signature of the client, which includes the CipherSwarm Agent version, operating system, and kernel architecture.
	clientSignature := "CipherSwarm Agent/" + AgentVersion + " " + info.OS + "/" + info.KernelArch

	devices, err := arch.GetDevices()
	if err != nil {
		logger.Error("Error getting devices: ", err)

	}

	agentMetadata := AgentMetadata{
		Name:            info.Hostname,
		ClientSignature: clientSignature,
		Devices:         devices,
	}

	AgentPlatform = info.OS

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

	resp, err := client.R().SetBody(agentMetadata).Put("/agents/" + strconv.Itoa(agentId))
	if err != nil {
		logger.Error("Error updating agent metadata: ", err)
	}

	if resp.IsSuccessState() {
		logger.Info("Agent metadata updated with the CipherSwarm API")
	} else {
		logger.Error("Error updating agent metadata: ", resp.String())
	}
}

type AgentMetadata struct {
	// Name represents the hostname of the agent client.
	Name string `json:"name"`
	// ClientSignature represents the signature of the client.
	ClientSignature string `json:"client_signature"`
	// Devices represents a list of device GPU names.
	Devices []string `json:"devices"`
	// OperatingSystem represents the operating system of the agent.
	// 0: Linux
	// 1: Windows
	// 2: MacOS
	OperatingSystem int `json:"operating_system"`
}

// Configuration represents the agent configuration.
var Configuration AgentConfiguration

// UpdateCracker checks for an updated version of the cracker and performs the necessary actions.
// It takes a client object as a parameter and uses it to make a request to check for updates.
// If an updated version is available, it logs the information about the latest version.
// If any errors occur during the process, they are logged as well.
func UpdateCracker(client *req.Client) {
	updateCrackerResponse := UpdateCrackerResponse{}
	logger.Info("Checking for updated cracker")
	currentVersion, err := GetCurrentHashcatVersion()
	if err != nil {
		logger.Error("Error getting current hashcat version: ", err)
	}

	resp := client.Get("/crackers/check_for_cracker_update").
		AddQueryParams("version", currentVersion).
		AddQueryParams("operating_system", AgentPlatform).Do()
	if resp.Err != nil {
		logger.Error("Error checking for updated cracker: ", resp.Err)
	}

	if resp.IsSuccessState() {
		err := resp.Into(&updateCrackerResponse)
		if err != nil {
			logger.Error("Error parsing response: ", err)
		}
		if updateCrackerResponse.Available {
			logger.Info("New cracker available: ", updateCrackerResponse.LatestVersion.Version)
		}
	} else {
		logger.Error("Error checking for updated cracker: ", resp.String())
	}
}

type UpdateCrackerResponse struct {
	// Available represents the availability status of the agent.
	// It is a boolean value indicating whether an updated agent is available or not.
	Available bool `json:"available"`
	// LatestVersion represents the latest version of the agent.
	LatestVersion struct {
		Id        int       `json:"id"`
		Name      string    `json:"name"`
		Version   string    `json:"version"`
		Active    bool      `json:"active"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	} `json:"latest_version"`
	// DownloadUrl represents the URL from which the file can be downloaded.
	DownloadUrl string `json:"download_url"`
}
