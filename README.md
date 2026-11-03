# HIPAA guardrails

A Claude Code plugin and CI check that keep protected health information (PHI) out of source code, tests, logs, AI coding sessions and vendors without a BAA, while you build healthcare software with AI coding agents. Every decision leaves a tamper-evident record with no patient data in it.

One checker (`plugins/hipaa-guardrails/scripts/guard.py`, Python standard library only) and one versioned policy file drive every layer, so Claude Code sessions, git commits and pull requests all meet the same rules.

This is an engineering control, not legal advice. Vendor BAA statuses and the other decisions listed in `docs/CONTROLS.md` belong to the policy owner and counsel.

| Layer | Where | What it does |
|---|---|---|
| Skill | `plugins/hipaa-guardrails/skills/` | The rules, loaded when Claude works on PHI-adjacent code |
| Hooks | `plugins/hipaa-guardrails/hooks/hooks.json` | Check prompts and every tool call before it runs: writes, edits, shell, reads, web, subagents, MCP |
| Pre-commit | `template-repo/.githooks/pre-commit` | Same check on what a commit records |
| CI | `template-repo/.github/workflows/` | Same check on what a PR adds, plus policy-change control and an evidence artifact |
| Evidence | `guard.py evidence ...` | Hash-chained record of every decision |

## Read first

- `docs/CONTROLS.md`: control matrix (HIPAA Security Rule and SOC 2 mapping) and the decisions that belong to people
- `docs/THREAT-MODEL.md`: what it stops, how it can be got around, and what closes each gap
- `docs/EVIDENCE.md`: record format, verification, retention, use in an audit
- `CHANGELOG.md`

## Layout

```
.claude-plugin/marketplace.json    -> marketplace "hipaa-guardrails"
plugins/hipaa-guardrails/
  .claude-plugin/plugin.json       -> version 0.2.0
  hooks/hooks.json                 -> PreToolUse (incl. WebFetch, WebSearch, Agent, MCP) + UserPromptSubmit
  scripts/guard.py                 -> the checker (hooks, pre-commit, CI, evidence)
  policy/default-policy.json       -> rules, patterns, vendor catalog (all 'unverified')
  skills/hipaa-guardrails/         -> SKILL.md + references
  commands/hipaa-check.md          -> /hipaa-guardrails:hipaa-check
docs/                              -> CONTROLS, EVIDENCE, THREAT-MODEL
tests/                             -> 120 tests, synthetic data only
template-repo/                     -> files to copy into every app that handles PHI
  .hipaa-guardrails.json           -> versioned per-repo policy (starts in warn mode)
  .claude/settings.json            -> enables the plugin for everyone who opens the repo
  .github/workflows/               -> PR check with evidence artifact; optional weekly full scan
  .github/CODEOWNERS               -> policy owner reviews policy and enforcement changes
  .githooks/pre-commit             -> git config core.hooksPath .githooks
  AGENTS.md, CLAUDE.md.snippet, gitignore.snippet
```

## Install

```
claude plugin marketplace add freemanlafleur/hipaa-guardrails
claude plugin install hipaa-guardrails@hipaa-guardrails
```

In an app repo, copy the files from `template-repo/`, then:

```
git config core.hooksPath .githooks
git update-index --chmod=+x .githooks/pre-commit
python3 ~/.claude/plugins/cache/hipaa-guardrails/hipaa-guardrails/*/scripts/guard.py validate-config
```

Git silently skips a hook without its executable bit, and `validate-config` flags that.

## Develop

```
python3 -m unittest discover -s tests -v
claude plugin validate ./plugins/hipaa-guardrails
python3 plugins/hipaa-guardrails/scripts/guard.py scan --all
```

Tests use synthetic values only, built at runtime so the repo itself never holds a real-format identifier.

## Organization overlays

The plugin code lives only here. An organization builds on it without forking:

- its own marketplace repo lists this plugin by git source, pinned to a release tag, so every developer gets the same reviewed version
- its own starter `.hipaa-guardrails.json` sets the policy owner, vendor BAA statuses, patient-data MCP tools, custom rules and whether a model runtime counts as covered; each app repo commits a copy and versions it
- its own template files point CI at this repo and a pinned tag

The checker merges each repo's `.hipaa-guardrails.json` over `policy/default-policy.json` (keys ending in `+` append to a list), so the defaults here stay the floor and the overlay only adds or tightens. CI lists anything that loosens them.

## Before it goes live

These are listed in `docs/CONTROLS.md` under "Decisions that belong to people":
- the policy owner and CODEOWNERS
- confirmed vendor statuses
- whether Bedrock counts as covered
- six-year evidence storage
- managed settings
