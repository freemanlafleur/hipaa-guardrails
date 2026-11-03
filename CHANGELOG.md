# Changelog

## 0.2.0 (draft, Nov 2 2026)

Hardened for audit use. Nothing published yet.

Packaged as a generic plugin that any organization can use, with organization-specific policy kept in separate overlay repos (marketplace, starter policy and templates).

### Coverage

**New identifier patterns:**
- SSN written without dashes next to a label, or with spaces
- HL7 v2 message segments
- Health plan member and Medicare/Medicaid ids
- Driver's license and passport numbers
- FHIR Patient resources with a birth date
- Tables whose header pairs a name with a birth date, SSN or MRN

**Unicode folding:**
- zero-width characters
- look-alike dashes
- full-width and other-script digits

**Data files.** Clinical exchange files (HL7, CCDA, DICOM, X12) and database dumps are denied. Tabular files are asked about. Binary files added in a PR are caught by name.

**Multi-line logging calls** are checked.

**Egress.** Prompts, WebFetch, WebSearch, Agent/Task subagents and MCP tool arguments are checked for identifiers and keys. MCP path arguments are checked against PHI paths.

**Reads.**
- File contents are sniffed before a read: one SSN or HL7 segment is enough, three hits for other identifiers, skipped for synthetic-marked files.
- `.env` reads are questioned.

**Shell.** These are checked as writes or reads of their real targets:
- redirects, `tee`, `sed -i` and `cp`/`mv` targets
- heredoc bodies
- Python and Node file writes
- `cd`, directory names
- one level of script indirection

### Integrity

- **Protected paths:** policy, baseline, Claude settings, git hooks, CI workflows, CODEOWNERS and the plugin's own install. Edits ask a person, even in warn mode.
- **Flagged commands:**
  - changing `core.hooksPath` (including `git -c`)
  - turning the plugin off from the CLI
  - `disableAllHooks`
  - `git commit -n`
  - `HUSKY=0` and similar
- **Broken config:** a repo config that can't be parsed falls back to the strict default policy.
- **Uncommitted hook:** `.githooks/pre-commit` committed without its executable bit is flagged (git skips such hooks silently).

### Governance

- **Config versioning:** `schema_version`, `policy_version`, `change_log` (version, date, approver, summary) and `requires_plugin`. `validate-config` checks keys, regexes, exceptions and versions.
- **CI policy-change control:**
  - A changed policy needs a version bump and an approved change_log entry.
  - Every loosening is listed.
  - A PR that loosens the policy is checked against the base branch's policy.
- **Exceptions registry** replaces free-text `phi-ok:` waivers:
  - Each exception needs an approver, a reason and an expiry of at most a year.
  - Line or path scope.
  - Rules about real PHI reaching sessions or tools, and guardrail-protection rules, can't be excepted.
  - Inline markers in shell commands never waive anything.

### Evidence

- A hash-chained JSONL record of every decision, with no file contents, prompts, commands or values. Paths are hashed for PHI-path rules.
- `evidence verify | report | export | head | path` commands.
- CI writes a step summary and an artifact.
- Full scans of every tracked file (`scan --all`) with an optional baseline, and a weekly workflow template.

### Tests

120 tests, covering:
- unicode evasion
- shell indirection
- guard tampering
- egress
- exceptions
- config failure
- evidence tampering and month-to-month chaining
- no value leaking into any output or record
- policy-change control
- the pre-commit hook against an installed plugin layout
- a 5,000-line performance budget

## 0.1.0 (Nov 2 2026)

First draft: skill, PreToolUse and UserPromptSubmit hooks, pre-commit hook, CI check, vendor catalog, first app config.
