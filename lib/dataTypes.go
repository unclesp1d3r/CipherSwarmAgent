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
		UseNativeHashcat    bool   `json:"use_native_hashcat" yaml:"use_native_hashcat"` // UseNativeHashcat specifies whether to use the native Hashcat implementation.
		AgentUpdateInterval int    `json:"agent_update_interval" yaml:"agent_update_interval"`
		BackendDevices      string `json:"backend_devices,omitempty" yaml:"backend_devices,omitempty"`
	} `json:"config" yaml:"config"`
	APIVersion int `json:"api_version" yaml:"api_version"` // ApiVersion represents the version of the API used by the agent client.
}

type AgentMetadata struct {
	// Name represents the hostname of the agent client.
	Name string `json:"name"`
	// ClientSignature represents the signature of the client.
	ClientSignature string `json:"client_signature"`
	// Devices represents a list of device GPU names.
	Devices []string `json:"devices"`
	// OperatingSystem represents the operating system of the agent.
	OperatingSystem string `json:"operating_system"`
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
	} `json:"latest_version,omitempty"`
	// DownloadUrl represents the URL from which the file can be downloaded.
	DownloadURL string `json:"download_url,omitempty"`
	ExecName    string `json:"exec_name,omitempty"`
	Message     string `json:"message,omitempty"`
}

type Task struct {
	ID        int       `json:"id"`
	AttackID  int       `json:"attack_id"`
	AgentID   int       `json:"agent_id"`
	StartDate time.Time `json:"start_date"`
	Limit     int64     `json:"limit"`
	Skip      int64     `json:"skip"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Status    string    `json:"status"`
	Available bool      `json:"available"`
}

type AttackParameters struct {
	ID                      int    `json:"id"`
	AttackMode              string `json:"attack_mode"`
	Mask                    string `json:"mask"`
	IncrementMode           bool   `json:"increment_mode"`
	IncrementMinimum        int    `json:"increment_minimum"`
	IncrementMaximum        int    `json:"increment_maximum"`
	Optimized               bool   `json:"optimized"`
	SlowCandidateGenerators bool   `json:"slow_candidate_generators"`
	WorkloadProfile         int    `json:"workload_profile"`
	DisableMarkov           bool   `json:"disable_markov"`
	ClassicMarkov           bool   `json:"classic_markov"`
	MarkovThreshold         int    `json:"markov_threshold"`
	LeftRule                string `json:"left_rule"`
	RightRule               string `json:"right_rule"`
	CustomCharset1          string `json:"custom_charset_1"`
	CustomCharset2          string `json:"custom_charset_2"`
	CustomCharset3          string `json:"custom_charset_3"`
	CustomCharset4          string `json:"custom_charset_4"`
	CrackerID               int    `json:"cracker_id"`
	HashListID              int    `json:"hash_list_id"`
	WordLists               []struct {
		ID          int    `json:"id"`
		DownloadURL string `json:"download_url"`
		Checksum    string `json:"checksum"` // base64 encoded md5 hash
		FileName    string `json:"file_name"`
	} `json:"word_lists"`
	RuleLists []struct {
		ID          int    `json:"id"`
		DownloadURL string `json:"download_url"`
		Checksum    string `json:"checksum"` // base64 encoded md5 hash
		FileName    string `json:"file_name"`
	} `json:"rule_lists"`
	HashMode         int    `json:"hash_mode"`
	HashListURL      string `json:"hash_list_url"`
	HashListChecksum string `json:"hash_list_checksum"`
	URL              string `json:"url"`
}

func (a *AttackParameters) GetAttackMode() uint8 {
	switch a.AttackMode {
	case "dictionary":
		return 0
	case "combinator":
		return 1
	case "mask":
		return 3
	case "hybrid-dictionary":
		return 6
	case "hybrid-mask":
		return 7
	default:
		return 0
	}
}

func (a *AttackParameters) GetWordlistFilenames() []string {
	var filenames []string
	for _, wordlist := range a.WordLists {
		filenames = append(filenames, wordlist.FileName)
	}
	return filenames
}

func (a *AttackParameters) GetRulelistFilenames() []string {
	var filenames []string
	for _, rulelist := range a.RuleLists {
		filenames = append(filenames, rulelist.FileName)
	}
	return filenames
}

type BenchmarkResult struct {
	Device    string `json:"device,omitempty"`
	HashType  string `json:"hash_type,omitempty"`
	RuntimeMs string `json:"runtime,omitempty"`
	SpeedHs   string `json:"hash_speed,omitempty"`
}
