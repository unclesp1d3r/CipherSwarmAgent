
<a name="v0.5.5"></a>

## [v0.5.5](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.5.4...v0.5.5)

> 2024-09-18

### Bug Fixes

* replace createTempFile with createOutFile

  Replaced createTempFile with createOutFile in the NewHashcatSession function. This makes the output file more deterministic and fixes an issue where restored tasks weren't sending their cracked hashes.



<a name="v0.5.4"></a>

## [v0.5.4](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.5.3...v0.5.4)

> 2024-09-12

### Code Refactoring

* Heavily cleanup and optimization.

* Refactored the agentClient


### Features

* Added initial Windows client support

  This is very experimental and has not been adequately tested. Since we haven’t tested it, use caution in this version. I firmly recommend not using the legacy device detection mode.



<a name="v0.5.3"></a>

## [v0.5.3](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.5.2...v0.5.3)

> 2024-08-29

### Bug Fixes

* Finished enabling support for opencl-devices


### Code Refactoring

* Code changes to try and make golangci-lint happy

* Minor cleanup of hashcat session code

* Minor code cleanup


### Features

* Devices are now identified using hashcat rather than a brittle shell script

  The system now runs a tiny attack job upon the agent’s startup, which verifies that the hashcat is working correctly and then identifies the devices detected by the hashcat. This is much more accurate than the legacy technique since it conforms to what hashcat will actually use.

* Added automatic hashcat capability

  The hashcat session will be stored in the data directory, and if one is detected, it will automatically attempt to resume it when starting the attack. When the attack is complete, the restore file will be removed.



<a name="v0.5.2"></a>

## [v0.5.2](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.5.1...v0.5.2)

> 2024-08-27

### Bug Fixes

* Fixed an issue causing SegFaults on weird HTTP errors

  There was a condition where an HTTP error outside of the 4XX and 5XX range could cause a seg fault. I added more error checking to ensure that it only throws a verbose error and doesn’t crash the agent.

* Fixed an issue causing SegFaults on weird HTTP errors

  There was a condition where an HTTP error outside of the 4XX and 5XX range could cause a seg fault. I added more error checking to ensure that it only throws a verbose error and doesn’t crash the agent.



<a name="v0.5.1"></a>

## [v0.5.1](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.5.0...v0.5.1)

> 2024-08-26

### Bug Fixes

* Added significant error checking to client to prevent nil crashes



<a name="v0.5.0"></a>

## [v0.5.0](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.4.2...v0.5.0)

> 2024-08-26

### Features

* Added support for mask list files from v0.5.0 of API



<a name="v0.4.2"></a>

## [v0.4.2](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.4.1...v0.4.2)

> 2024-08-06

### Bug Fixes

* Upgraded to support version v0.7.2 of API

  The API was refactored, introducing breaking changes in the SDK, so we needed to rename some packages and objects.


### Code Refactoring

* Minor cleanup to meet formatting standards



<a name="v0.4.1"></a>

## [v0.4.1](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.4.0...v0.4.1)

> 2024-07-31

### Bug Fixes

* Automatic benchmark now performs all hash types

  Since the benchmarking function determines what hash types this agent supports, we needed to change the feature to benchmark all hash types, not just the common ones. The agent’s initial startup is significantly slower now but supports more functionality. This can be turned off by setting `enable_additional_hash_types: false` in the agent config.



<a name="v0.4.0"></a>

## [v0.4.0](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.3.1...v0.4.0)

> 2024-07-29

### Features

* Added support for bidirectional status on status updates

  This enables running tasks to be notified of hashes cracked in another task and pause tasks currently running.

We also added support for using a shared directory as a zap synchronization point. If configured, cracked hashes will be written to a directory, and the client will monitor that directory for new zaps.



<a name="v0.3.1"></a>

## [v0.3.1](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.3...v0.3.1)

> 2024-07-23

### Bug Fixes

* Tasks are accepted before the downloads start



<a name="v0.3"></a>

## [v0.3](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.8...v0.3)

> 2024-07-12

### Bug Fixes

* Fixed issue with always_use_native_hashcat on server messing up the client

  When the server setting was set for the agent, the agent was not finding hashcat, but also not allowing it to be set via config or environment variable.

* Removed exessive output in standard debugging

* Files directory can be set separate of the data dir

* Replaced tail library with one still maintained


### Features

* Add support for zaps



<a name="v0.2.8"></a>

## [v0.2.8](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.7...v0.2.8)

> 2024-07-10

### Bug Fixes

* Added more checking for null tasks or attacks



<a name="v0.2.7"></a>

## [v0.2.7](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.6...v0.2.7)

> 2024-07-01

### Code Refactoring

* Moved utility code out of agentClient.go



<a name="v0.2.6"></a>

## [v0.2.6](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.5...v0.2.6)

> 2024-06-21

### Bug Fixes

* Correctly handle when a running task is deleted



<a name="v0.2.5"></a>

## [v0.2.5](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.4...v0.2.5)

> 2024-06-17

### Bug Fixes

* Fix incorrect status and benchmark output

  The benchmark was incorrectly sending the time in ms to complete a hash instead of the number of hashes per second. Additionally, the cracked count was always 2, which wrong.



<a name="v0.2.4"></a>

## [v0.2.4](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.3...v0.2.4)

> 2024-06-16

### Bug Fixes

* Updated to support v0.4.1 of CipherSwarm SDK

* Docker now finds hashcat correctly


### Features

* Added the ability to override checking checksums

  This is useful when you set the data directory to be a network share



<a name="v0.2.3"></a>

## [v0.2.3](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.2...v0.2.3)

> 2024-06-16

### Bug Fixes

* Updated to support v0.4.1 of CipherSwarm SDK

* Docker now finds hashcat correctly


### Features

* Added the ability to override checking checksums

  This is useful when you set the data directory to be a network share



<a name="v0.2.2"></a>

## [v0.2.2](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.1...v0.2.2)

> 2024-06-14


<a name="v0.2.1"></a>

## [v0.2.1](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.2.0...v0.2.1)

> 2024-06-14

### Bug Fixes

* Handle failure of getting agent config



<a name="v0.2.0"></a>

## [v0.2.0](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.11...v0.2.0)

> 2024-06-14

### Bug Fixes

* Download files are now compare checksums correctly


### Features

* Agent now tells server its offline when shutting down

  This marks the agent offline and frees up the tasks to be handled by another agent.

* Add bidirectional status

  Benchmarks are now determined by the server on the heartbeat.

* Added error metadata



<a name="v0.1.11"></a>

## [v0.1.11](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.10...v0.1.11)

> 2024-06-01

### Bug Fixes

* Fixed failure on dangling lock

  Fixed the bug where the agent died if there was a dangling lock.pid


### Features

* Add support for the agent error API

  The agent will now send any errors to the server for collection.

* Add parallel file downloads

  Replaced  the word and rule file downloads to use go-getter in parallel using go routines



<a name="v0.1.10"></a>

## [v0.1.10](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.9...v0.1.10)

> 2024-05-28

### Features

* Add parallel file downloads

  Replaced  the word and rule file downloads to use go-getter in parallel using go routines



<a name="v0.1.9"></a>

## [v0.1.9](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.8...v0.1.9)

> 2024-05-21

### Code Refactoring

* Move to v0.2.0 of the SDK

  Version 0.2.0 introduced major breaking changes.



<a name="v0.1.8"></a>

## [v0.1.8](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.7...v0.1.8)

> 2024-05-15


<a name="v0.1.7"></a>

## [v0.1.7](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.6...v0.1.7)

> 2024-05-15

### CI Changes

* Add SBOM to goreleaser config

* Fix git-chglog missing config_dir


### Code Refactoring

* Update to latest Agent SDK v0.1.9



<a name="v0.1.6"></a>

## [v0.1.6](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.5...v0.1.6)

> 2024-05-13

### Features

* Added improved changelog support



<a name="v0.1.5"></a>

## [v0.1.5](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.4...v0.1.5)

> 2024-05-09


<a name="v0.1.4"></a>

## [v0.1.4](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.3...v0.1.4)

> 2024-05-07


<a name="v0.1.3"></a>

## [v0.1.3](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.2...v0.1.3)

> 2024-05-06


<a name="v0.1.2"></a>

## [v0.1.2](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.1...v0.1.2)

> 2024-05-06


<a name="v0.1.1"></a>

## [v0.1.1](https://github.com/unclesp1d3r/CipherSwarmAgent/compare/v0.1.0...v0.1.1)

> 2024-05-01


<a name="v0.1.0"></a>

## v0.1.0

> 2024-04-30

