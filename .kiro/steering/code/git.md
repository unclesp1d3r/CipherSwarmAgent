---
inclusion: fileMatch
fileMatchPattern: ['**/.git/*']
---
- **Commit Strategies:**

# Git Best Practices for CipherSwarmAgent

- **Atomic Commits:** Make each commit a single, logical change. Never commit broken or untested code.
- **Conventional Commits:** Use [Conventional Commits](mdc:https:/www.conventionalcommits.org) for all commit messages. Example: `fix(agent): handle nil pointer in hashcat session`.
- **Feature Branch Workflow:**
    - Create a new branch for each feature, bugfix, or refactor.
    - Keep branches short-lived and up-to-date with `main` via rebase or merge.
    - Never commit directly to `main`. All changes go through pull requests.
- **Pull Requests & Code Review:**
    - All changes require a PR and at least one review.
    - Address feedback promptly and keep discussions focused on code quality and correctness.
    - Use the PR template and checklist if provided.
- **.gitignore Hygiene:**
    - Ensure all build artifacts, IDE files, and secrets/configs (e.g., `data/`, `cipherswarmagent.yaml`) are ignored.
    - Never commit secrets, credentials, or sensitive data. Use environment variables and secret managers.
- **CI Integration:**
    - All commits and PRs must pass CI (lint, test, build) before merge.
    - Use GitHub Actions for automated checks and releases.
- **Tagging & Releases:**
    - Tag releases with semantic versioning (e.g., `v0.3.0`).
    - Use annotated tags for release notes.
- **Repository Maintenance:**
    - Regularly prune stale branches after merge.
    - Use `git gc` as needed to optimize repo performance.
- **Common Pitfalls:**
    - Never commit large files, secrets, or generated data.
    - Resolve merge conflicts carefully and test after resolving.
    - Always check `.gitignore` before adding new files.
