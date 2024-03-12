package lib

import "time"

type AgentAuthenticationResult struct {
	// Authenticated represents the authentication status of the agent client.
	Authenticated bool `json:"authenticated"`
	// AgentId represents the unique identifier of the agent.
	AgentID int `json:"agent_id"`
}

type AgentConfiguration struct {
	Config struct {
		// UseNativeHashcat specifies whether to use the native Hashcat implementation.
		// If set to true, the agent will use the native Hashcat implementation.
		// If set to false, the agent will use a different implementation.
		UseNativeHashcat    bool `json:"use_native_hashcat" yaml:"use_native_hashcat"`
		AgentUpdateInterval int  `json:"agent_update_interval" yaml:"agent_update_interval"`
	} `json:"config" yaml:"config"`
	// ApiVersion represents the version of the API used by the agent client.
	// It is specified as an integer and is used for JSON and YAML serialization.
	APIVersion int `json:"api_version" yaml:"api_version"`
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
	// 2: Darwin (macOS)
	OperatingSystem int `json:"operating_system"`
}

type UpdateCrackerResponse struct {
	// Available represents the availability status of the agent.
	// It is a boolean value indicating whether an updated agent is available or not.
	Available bool `json:"available"`
	// LatestVersion represents the latest version of the agent.
	LatestVersion struct {
		ID        int       `json:"id"`
		Name      string    `json:"name"`
		Version   string    `json:"version"`
		Active    bool      `json:"active"`
		CrackerID int       `json:"cracker_id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	} `json:"latest_version"`
	// DownloadUrl represents the URL from which the file can be downloaded.
	DownloadURL string `json:"download_url"`
	ExecName    string `json:"exec_name"`
}
