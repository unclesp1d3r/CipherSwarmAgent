# Changelog

All notable changes to this project will be documented in this file.

## [0.6.1] - 2026-02-27

### Features

- Introduce new agent and configuration management

- Upgrade agent sdk to v0.9.0 ([#107](https://github.com/EvilBit-Labs/opnDossier/pull/107))

- Add fault tolerance improvements for resilience

- Implement intelligent hashcat error parsing and classification

- Add prompts for Continuous Integration Check and Simplicity Review

- Add mise.lock file with tool configurations

- **dev**: Add oapi-codegen to mise.toml as dev tool

- Persistent benchmark caching with retry mechanism ([#117](https://github.com/EvilBit-Labs/opnDossier/pull/117))

- Submit benchmarks incrementally with per-item tracking ([#131](https://github.com/EvilBit-Labs/opnDossier/pull/131))

- Add missing CLI flags and architecture remediation ([#133](https://github.com/EvilBit-Labs/opnDossier/pull/133))


### Bug Fixes

- Fix hashlist download error handling ([#56](https://github.com/EvilBit-Labs/opnDossier/pull/56))

- **hashcat**: Fix CI linting issues - move constructor and use CommandContext

- Resolve all golangci-lint issues across codebase

- Correct nolint placement for gosec exception in Extract7z

- Resolve all golangci-lint issues across codebase

- **deps**: Update module github.com/shirou/gopsutil/v3 to v4

- Use structured logging in UpdateAgentMetadata error handling

- Resolve variable shadowing of state package in heartbeat functions

- Prevent silent failure on zero maxRetries and improve error logging

- Address PR review comments for error parsing implementation

- Report restore-file failures before early return

- Address PR review findings for error handling

- Address PR review findings for error handling

- Improve observability for silent corrections and fix test docs

- Improve error handling, context propagation, and code modernization

- Address PR review findings for error handling, comments, and security

- Restore mise.toml after accidental overwrite ([#116](https://github.com/EvilBit-Labs/opnDossier/pull/116))

- **ci**: Require lgtm label in Mergify queue conditions ([#128](https://github.com/EvilBit-Labs/opnDossier/pull/128))

- **task**: Clean up job output files after completion or cancellation ([#135](https://github.com/EvilBit-Labs/opnDossier/pull/135))

- **release**: Remove go generate from goreleaser hooks

- Resolve code review issues from go-review audit ([#143](https://github.com/EvilBit-Labs/opnDossier/pull/143))

- Remove stale cracker update calls causing 404s ([#145](https://github.com/EvilBit-Labs/opnDossier/pull/145))


### Refactor

- **hashcat**: Improve documentation and comments in session.go and types.go

- **hashcat**: Improve documentation and comments in params.go and cracker.go

- **hashcat**: Simplify restore file check logic in session creation

- **hashcat**: Improve documentation and comments in session.go and types.go

- **hashcat**: Simplify restore file check logic in session creation

- Rename shared package to state to fix revive lint error

- Consolidate error handling and improve test coverage ([#105](https://github.com/EvilBit-Labs/opnDossier/pull/105))

- Update Go modernization commands and benchmark output handling

- Extract domain packages from lib/ god package ([#134](https://github.com/EvilBit-Labs/opnDossier/pull/134))

- Complete context.Context propagation through error handling ([#115](https://github.com/EvilBit-Labs/opnDossier/pull/115)) ([#136](https://github.com/EvilBit-Labs/opnDossier/pull/136))


### Documentation

- Update mkdocs configuration and enhance documentation structure

- Update cursorrules.md to reference new API contract location

- Add GEMINI.md for Gemini System Prompt documentation

- Add learnings to AGENTS.md for AI assistants

- Add learnings to AGENTS.md for AI assistants

- **agents**: Add releasing section and must-complete pattern


### Styling

- Align struct field comments in Session

- Replace interface{} with any in config tests

- Fix testifylint and gocritic warnings


### Testing

- Add initial unit test for clientUtils

- Improve base64ToHex unit tests ([#57](https://github.com/EvilBit-Labs/opnDossier/pull/57))

- Add comprehensive tests for downloadWithRetry function

- Add configuration defaults verification tests

- Add proper error assertions in TestSendHeartBeat

- Add task runner tests for parseExitCode and handler functions

- Add heartbeat backoff calculation tests


### Miscellaneous Tasks

- Add architecture and coding guidelines documentation

- Add initial documentation and configuration files

- Add configuration and testing documentation

- Add Go SDK development rules and implementation plan

- Streamline justfile by removing usage comments

- Update project configuration and linting setup

- Update dependencies and enhance justfile for dependency management

- Update project files for consistency and clarity

- Update project configuration and enhance logging

- Added requirements management rules.

- Update dependencies and improve context handling

- Specify tool versions in mise.toml

- Update justfile and mise.toml for mkdocs setup

- Add VSCode settings for Go tool configuration

- Update VSCode settings for ruff and add CLAUDE.md reference

- Update configuration files and dependencies for improved tooling support

- Add .claude.local.md to .gitignore for local configuration exclusion

- Bump golangci-lint to 2.10.1 and fix review findings


## [0.5.7] - 2024-12-19

### Miscellaneous Tasks

- Update dependencies in go.mod to latest versions

- Updated change log

- Remove obsolete entries from go.sum


## [0.5.6] - 2024-10-04

### Features

- Add command line flags for Viper configuration options ([#49](https://github.com/EvilBit-Labs/opnDossier/pull/49))

- Update changelog configuration


### Bug Fixes

- Enhance hashcat binary location logic


### Refactor

- Improve findHashcatBinary function documentation

- Divide up large library files into single responsibility files ([#53](https://github.com/EvilBit-Labs/opnDossier/pull/53))


### Documentation

- Simplify and condense function comments


### Miscellaneous Tasks

- Add vcs configuration file

- Update dependency versions and fix agent update request

- Update Go and dependencies in go.mod

- Update changelog with v0.5.6 release details


## [0.5.5] - 2024-09-19

### Bug Fixes

- Replace createTempFile with createOutFile


### Documentation

- Update Docker run command in README.md

- Simplify and clarify function comments


### Miscellaneous Tasks

- Updated CHANGELOG.md


## [0.5.4] - 2024-09-13

### Features

- Added initial Windows client support


### Refactor

- Refactored the agentClient

- Heavily cleanup and optimization.


### Miscellaneous Tasks

- Bumped dependencies

- Bundle dependencies

- Updated changelog


## [0.5.3] - 2024-08-30

### Features

- Added automatic hashcat capability

- Devices are now identified using hashcat rather than a brittle shell script


### Bug Fixes

- Finished enabling support for opencl-devices


### Refactor

- Minor code cleanup

- Minor cleanup of hashcat session code

- Code changes to try and make golangci-lint happy


### Miscellaneous Tasks

- Updated CHANGELOG

- Update changelog

- Updated changelog


## [0.5.2] - 2024-08-27

### Bug Fixes

- Fixed an issue causing SegFaults on weird HTTP errors

- Fixed an issue causing SegFaults on weird HTTP errors


### Miscellaneous Tasks

- Updated ChangeLog


## [0.5.1] - 2024-08-27

### Bug Fixes

- Added significant error checking to client to prevent nil crashes


### Miscellaneous Tasks

- Updated CHANGELOG


## [0.5.0] - 2024-08-26

### Features

- Added support for mask list files from v0.5.0 of API


### Miscellaneous Tasks

- Update changelog


## [0.4.2] - 2024-08-07

### Bug Fixes

- Upgraded to support version v0.7.2 of API


### Refactor

- Minor cleanup to meet formatting standards


### Documentation

- Minor grammar changes to the README


### Miscellaneous Tasks

- Updated changelog


## [0.4.1] - 2024-08-01

### Bug Fixes

- Automatic benchmark now performs all hash types


### Miscellaneous Tasks

- Updated changelog


## [0.4.0] - 2024-07-30

### Features

- Added support for bidirectional status on status updates


### Miscellaneous Tasks

- Updated changelog


## [0.3.1] - 2024-07-24

### Bug Fixes

- Tasks are accepted before the downloads start


### Miscellaneous Tasks

- Bumped chglog

- Updated changelog


## [0.3] - 2024-07-13

### Features

- Add support for zaps


### Bug Fixes

- Replaced tail library with one still maintained

- Files directory can be set separate of the data dir

- Removed excessive output in standard debugging

- Fixed issue with always_use_native_hashcat on server messing up the client


### Miscellaneous Tasks

- Bumped dependencies

- Updated changelog and bumped version number


## [0.2.8] - 2024-07-10

### Bug Fixes

- Added more checking for null tasks or attacks


### Miscellaneous Tasks

- Bumped module versions

- Updated changelog


## [0.2.7] - 2024-07-01

### Refactor

- Moved utility code out of agentClient.go


### Miscellaneous Tasks

- Updated Changelog


## [0.2.6] - 2024-06-21

### Bug Fixes

- Correctly handle when a running task is deleted


### Miscellaneous Tasks

- Update changelog


## [0.2.5] - 2024-06-18

### Bug Fixes

- Fix incorrect status and benchmark output


### Miscellaneous Tasks

- Update changelog


## [0.2.4] - 2024-06-17

### Features

- Added error metadata

- Add bidirectional status

- Agent now tells server its offline when shutting down

- Added the ability to override checking checksums


### Bug Fixes

- Download files are now compare checksums correctly

- Handle failure of getting agent config

- Docker now finds hashcat correctly

- Updated to support v0.4.1 of CipherSwarm SDK


### Miscellaneous Tasks

- Remove boring stuff from changelog

- Updated changelog

- Updated goreleaser config format

- Updated changelog

- Updated changelog

- Bumped version tag


## [0.1.11] - 2024-06-02

### Features

- Add parallel file downloads

- Add support for the agent error API


### Bug Fixes

- Fixed failure on dangling lock


### Miscellaneous Tasks

- Updated changelog

- Updated changelog


## [0.1.10] - 2024-05-29

### Features

- Add parallel file downloads


### Miscellaneous Tasks

- Update changelog

- Updated changelog


## [0.1.9] - 2024-05-22

### Refactor

- Move to v0.2.0 of the SDK


### Documentation

- Updated change logs

- Update change log


### Miscellaneous Tasks

- Bumped versions on dependencies

- Updated Changelog


## [0.1.7] - 2024-05-16

### Refactor

- Update to latest Agent SDK v0.1.9


### Documentation

- Add note about Conventional Commits

- Updated changelog


### Styling

- Add gitlint to enforce conventional commits


### Miscellaneous Tasks

- Add changelog action

- Fix git-chglog missing config_dir

- Add SBOM to goreleaser config


### Revert

- Remove non-working git-chglog action


## [0.1.6] - 2024-05-14

### Features

- Added improved changelog support


## [0.1.0] - 2024-04-30

<!-- generated by git-cliff -->
