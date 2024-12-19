
<a name="v0.5.7"></a>

## [v0.5.7](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.5.6...v0.5.7)

> 2024-12-18

### Maintenance Changes 🧹

* update dependencies in go.mod to latest versions



<a name="v0.5.6"></a>

## [v0.5.6](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.5.5...v0.5.6)

> 2024-10-03

### Bug Fixes 🐛

* enhance hashcat binary location logic

  Replaced direct exec.LookPath calls with a more robust findHashcatBinary function. This function searches multiple predefined paths and the user's $PATH, improving binary location reliability and simplifying version retrieval logic.


### Code Refactoring 🛠

* divide up large library files into single responsibility files ([#53](https://github.com/unclesp1d3r/CipherSwarm/issues/53))

  This commit moves the previous functions in agentClient and clientUtils into purpose-specific files. The overall codebase is now more maintainable and easier to navigate.

* improve findHashcatBinary function documentation

  Updated the documentation for the findHashcatBinary function to clarify its behavior and error handling. Replaced redundant variable names for consistency and removed obsolete fetchHashcatVersion function.


### Documentation Changes 📚

* simplify and condense function comments

  Revised comments to be more succinct and direct.

Reduced verbosity and removed redundant details to improve readability. Condensed function descriptions to highlight main actions and outcomes while preserving essential context.


### Features 🚀

* update changelog configuration

  Updated the repository URL and added filtering and sorting options. Expanded commit groups settings to include new types and reordered titles with emoji icons. Improved header pattern, added issue prefixes, and refined merge and revert patterns for better clarity.

* Add command line flags for Viper configuration options ([#49](https://github.com/unclesp1d3r/CipherSwarm/issues/49))

  * feat: Add command line flags for Viper configuration options


Add command line flags for Viper configuration options in `cmd/root.go`.

* Add command line flags for `API_TOKEN`, `API_URL`, `DATA_PATH`, `GPU_TEMP_THRESHOLD`, `ALWAYS_USE_NATIVE_HASHCAT`, `SLEEP_ON_FAILURE`, `FILES_PATH`, `EXTRA_DEBUGGING`, `STATUS_TIMER`, `WRITE_ZAPS_TO_FILE`, `ZAP_PATH`, and `RETAIN_ZAPS_ON_COMPLETION`.
* Bind each flag to its corresponding Viper configuration in the `init` function.
* Add proper descriptions for each command line flag in the viper settings.

---


* Add command line flags and update README

* Add command line flags for various configuration options in `cmd/root.go`
* Bind each flag to its corresponding Viper configuration in the `init` function
* Update `setDefaultConfigValues` function to set default values for new configuration options
* Add single letter flag aliases for each command line flag
* Update `README.md` to include new command line flags and mention `--help` and `--version` flags

* chore: simplify init function documentation

Update the init function comment for clarity and brevity. The revised comment concisely explains the initialization process and the binding of flags to the configuration.


---------


### Maintenance Changes 🧹

* update changelog with v0.5.6 release details

* update Go and dependencies in go.mod

  Updated Go version and multiple dependencies to their latest versions. This includes upgrades for various Google Cloud libraries, OpenTelemetry components, and others to improve security and performance.

* update dependency versions and fix agent update request

  Updated multiple dependencies in `go.mod` to their latest versions. Corrected field name from `Name` to `HostName` in agent update request.

* add vcs configuration file

  Introduce VCS configuration file to ensure consistent commit message format and enable Git integration. This includes setting up inspection profiles and directory mappings for version control.


### Reverts

* Add utility methods for file operations and task management


<a name="v0.5.5"></a>

## [v0.5.5](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.5.4...v0.5.5)

> 2024-09-18

### Bug Fixes 🐛

* replace createTempFile with createOutFile

  Replaced createTempFile with createOutFile in the NewHashcatSession function. This makes the output file more deterministic and fixes an issue where restored tasks weren't sending their cracked hashes.


### Documentation Changes 📚

* simplify and clarify function comments

  Simplify and refine the documentation comments for functions to enhance readability and conciseness. Updated comments describe the core actions performed by each function while removing excessive details and steps.

* Update Docker run command in README.md


### Maintenance Changes 🧹

* Updated CHANGELOG.md



<a name="v0.5.4"></a>

## [v0.5.4](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.5.3...v0.5.4)

> 2024-09-12

### Code Refactoring 🛠

* Heavily cleanup and optimization.

* Refactored the agentClient


### Features 🚀

* Added initial Windows client support

  This is very experimental and has not been adequately tested. Since we haven’t tested it, use caution in this version. I firmly recommend not using the legacy device detection mode.


### Maintenance Changes 🧹

* Updated changelog

* Bundle dependencies

* Bumped dependencies



<a name="v0.5.3"></a>

## [v0.5.3](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.5.2...v0.5.3)

> 2024-08-29

### Bug Fixes 🐛

* Finished enabling support for opencl-devices


### Code Refactoring 🛠

* Code changes to try and make golangci-lint happy

* Minor cleanup of hashcat session code

* Minor code cleanup


### Features 🚀

* Devices are now identified using hashcat rather than a brittle shell script

  The system now runs a tiny attack job upon the agent’s startup, which verifies that the hashcat is working correctly and then identifies the devices detected by the hashcat. This is much more accurate than the legacy technique since it conforms to what hashcat will actually use.

* Added automatic hashcat capability

  The hashcat session will be stored in the data directory, and if one is detected, it will automatically attempt to resume it when starting the attack. When the attack is complete, the restore file will be removed.


### Maintenance Changes 🧹

* Updated changelog

* Update changelog

* Updated CHANGELOG



<a name="v0.5.2"></a>

## [v0.5.2](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.5.1...v0.5.2)

> 2024-08-27

### Bug Fixes 🐛

* Fixed an issue causing SegFaults on weird HTTP errors

* Fixed an issue causing SegFaults on weird HTTP errors


### Maintenance Changes 🧹

* Updated ChangeLog



<a name="v0.5.1"></a>

## [v0.5.1](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.5.0...v0.5.1)

> 2024-08-26

### Bug Fixes 🐛

* Added significant error checking to client to prevent nil crashes


### Maintenance Changes 🧹

* Updated CHANGELOG



<a name="v0.5.0"></a>

## [v0.5.0](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.4.2...v0.5.0)

> 2024-08-26

### Features 🚀

* Added support for mask list files from v0.5.0 of API


### Maintenance Changes 🧹

* Update changelog



<a name="v0.4.2"></a>

## [v0.4.2](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.4.1...v0.4.2)

> 2024-08-06

### Bug Fixes 🐛

* Upgraded to support version v0.7.2 of API

  The API was refactored, introducing breaking changes in the SDK, so we needed to rename some packages and objects.


### Code Refactoring 🛠

* Minor cleanup to meet formatting standards


### Documentation Changes 📚

* Minor grammar changes to the README


### Maintenance Changes 🧹

* Updated changelog



<a name="v0.4.1"></a>

## [v0.4.1](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.4.0...v0.4.1)

> 2024-07-31

### Bug Fixes 🐛

* Automatic benchmark now performs all hash types

  Since the benchmarking function determines what hash types this agent supports, we needed to change the feature to benchmark all hash types, not just the common ones. The agent’s initial startup is significantly slower now but supports more functionality. This can be turned off by setting `enable_additional_hash_types: false` in the agent config.


### Maintenance Changes 🧹

* Updated changelog



<a name="v0.4.0"></a>

## [v0.4.0](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.3.1...v0.4.0)

> 2024-07-29

### Features 🚀

* Added support for bidirectional status on status updates

  This enables running tasks to be notified of hashes cracked in another task and pause tasks currently running.

We also added support for using a shared directory as a zap synchronization point. If configured, cracked hashes will be written to a directory, and the client will monitor that directory for new zaps.


### Maintenance Changes 🧹

* Updated changelog



<a name="v0.3.1"></a>

## [v0.3.1](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.3...v0.3.1)

> 2024-07-23

### Bug Fixes 🐛

* Tasks are accepted before the downloads start


### Maintenance Changes 🧹

* Updated changelog

* Bumped chglog



<a name="v0.3"></a>

## [v0.3](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.8...v0.3)

> 2024-07-12

### Bug Fixes 🐛

* Fixed issue with always_use_native_hashcat on server messing up the client

  When the server setting was set for the agent, the agent was not finding hashcat, but also not allowing it to be set via config or environment variable.

* Removed exessive output in standard debugging

* Files directory can be set separate of the data dir

* Replaced tail library with one still maintained


### Features 🚀

* Add support for zaps


### Maintenance Changes 🧹

* Updated changelog and bumped version number

* Bumped dependencies



<a name="v0.2.8"></a>

## [v0.2.8](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.7...v0.2.8)

> 2024-07-10

### Bug Fixes 🐛

* Added more checking for null tasks or attacks


### Maintenance Changes 🧹

* Updated changelog

* Bumped module versions



<a name="v0.2.7"></a>

## [v0.2.7](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.6...v0.2.7)

> 2024-07-01

### Code Refactoring 🛠

* Moved utility code out of agentClient.go


### Maintenance Changes 🧹

* Updated Changelog



<a name="v0.2.6"></a>

## [v0.2.6](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.5...v0.2.6)

> 2024-06-21

### Bug Fixes 🐛

* Correctly handle when a running task is deleted


### Maintenance Changes 🧹

* Update changelog



<a name="v0.2.5"></a>

## [v0.2.5](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.4...v0.2.5)

> 2024-06-17

### Bug Fixes 🐛

* Fix incorrect status and benchmark output


### Maintenance Changes 🧹

* Update changelog



<a name="v0.2.4"></a>

## [v0.2.4](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.3...v0.2.4)

> 2024-06-16

### Bug Fixes 🐛

* Updated to support v0.4.1 of CipherSwarm SDK

* Docker now finds hashcat correctly


### Features 🚀

* Added the ability to override checking checksums

  This is useful when you set the data directory to be a network share


### Maintenance Changes 🧹

* Bumped version tag

* updated changelog



<a name="v0.2.3"></a>

## [v0.2.3](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.2...v0.2.3)

> 2024-06-16

### Bug Fixes 🐛

* Updated to support v0.4.1 of CipherSwarm SDK

* Docker now finds hashcat correctly


### Features 🚀

* Added the ability to override checking checksums

  This is useful when you set the data directory to be a network share


### Maintenance Changes 🧹

* updated changelog



<a name="v0.2.2"></a>

## [v0.2.2](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.1...v0.2.2)

> 2024-06-14

### Maintenance Changes 🧹

* Updated changelog

* Updated goreleaser config format



<a name="v0.2.1"></a>

## [v0.2.1](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.2.0...v0.2.1)

> 2024-06-14

### Bug Fixes 🐛

* Handle failure of getting agent config


### Maintenance Changes 🧹

* updated changelog



<a name="v0.2.0"></a>

## [v0.2.0](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.11...v0.2.0)

> 2024-06-14

### Bug Fixes 🐛

* Download files are now compare checksums correctly


### Features 🚀

* Agent now tells server its offline when shutting down

  This marks the agent offline and frees up the tasks to be handled by another agent.

* Add bidirectional status

  Benchmarks are now determined by the server on the heartbeat.

* Added error metadata


### Maintenance Changes 🧹

* updated changelog

* Remove boring stuff from changelog



<a name="v0.1.11"></a>

## [v0.1.11](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.10...v0.1.11)

> 2024-06-01

### Bug Fixes 🐛

* Fixed failure on dangling lock

  Fixed the bug where the agent died if there was a dangling lock.pid


### Features 🚀

* Add support for the agent error API

  The agent will now send any errors to the server for collection.

* Add parallel file downloads

  Replaced  the word and rule file downloads to use go-getter in parallel using go routines


### Maintenance Changes 🧹

* Updated changelog

* Updated changelog



<a name="v0.1.10"></a>

## [v0.1.10](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.9...v0.1.10)

> 2024-05-28

### Features 🚀

* Add parallel file downloads

  Replaced  the word and rule file downloads to use go-getter in parallel using go routines


### Maintenance Changes 🧹

* Updated changelog

* Update changelog



<a name="v0.1.9"></a>

## [v0.1.9](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.8...v0.1.9)

> 2024-05-21

### Code Refactoring 🛠

* Move to v0.2.0 of the SDK


### Documentation Changes 📚

* Update change log

* Updated change logs


### Maintenance Changes 🧹

* Updated Changelog

* Bumped versions on dependencies



<a name="v0.1.8"></a>

## [v0.1.8](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.7...v0.1.8)

> 2024-05-15


<a name="v0.1.7"></a>

## [v0.1.7](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.6...v0.1.7)

> 2024-05-15

### Code Refactoring 🛠

* Update to latest Agent SDK v0.1.9


### Documentation Changes 📚

* Updated changelog

* Add note about Conventional Commits


### Maintenance Changes 🧹

* Add changelog action


### Style Changes 🎨

* Add gitlint to enforce conventional commits



<a name="v0.1.6"></a>

## [v0.1.6](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.5...v0.1.6)

> 2024-05-13

### Features 🚀

* Added improved changelog support



<a name="v0.1.5"></a>

## [v0.1.5](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.4...v0.1.5)

> 2024-05-09


<a name="v0.1.4"></a>

## [v0.1.4](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.3...v0.1.4)

> 2024-05-07


<a name="v0.1.3"></a>

## [v0.1.3](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.2...v0.1.3)

> 2024-05-06


<a name="v0.1.2"></a>

## [v0.1.2](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.1...v0.1.2)

> 2024-05-06


<a name="v0.1.1"></a>

## [v0.1.1](https://github.com/unclesp1d3r/CipherSwarm/compare/v0.1.0...v0.1.1)

> 2024-05-01


<a name="v0.1.0"></a>

## v0.1.0

> 2024-04-30

