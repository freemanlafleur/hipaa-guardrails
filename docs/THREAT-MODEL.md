# Threat model and known limits

The guardrails are a seatbelt for a development workflow, not proof of compliance. This page says what they're built to stop, how they can be got around, and what closes each gap.

## Who we're protecting against

| Actor | Example | Primary defense |
|---|---|---|
| A well-meaning developer in a hurry | Pastes a real chart into a prompt to reproduce a bug; logs a whole request body | Hooks and pre-commit, with a message that names the rule and the fix |
| An AI agent making a mistake | Reads an export folder to "understand the data"; writes a fixture with realistic identifiers; adds an SDK for a vendor with no BAA | Hooks (PreToolUse runs on every tool call, subagents included) |
| An AI agent following injected instructions | A web page or file tells the agent to switch off hooks, edit the policy or send data to a URL | GUARD-* rules ask a person first; PHI-EGRESS on web and MCP calls; the skill tells the agent never to touch guardrails files |
| An insider who wants to bypass the checks | Disables the plugin, skips git hooks, loosens the policy in the same PR as the code | CI on every PR with the base branch's policy, CODEOWNERS, branch protection, managed settings |

## What's covered in 0.2.0

**Unicode tricks.** These are folded away before matching:
- zero-width characters
- look-alike dashes
- full-width and other-script digits

**Shell indirection.** These are checked as writes or reads of their real targets:
- redirects, `tee` and `sed -i`
- heredocs
- `cp`/`mv`
- Python and Node file writes
- `cd` into folders
- directory names
- one level of script indirection (`bash run.sh`, `python3 x.py`)

**Content sniffing before a read.** The first 256 KB of a file is checked before it's read into a session. One SSN or HL7 segment is enough to block. Other identifiers need three hits, so a single sample value in a source file doesn't block it.

**Egress.** Prompts, web fetches, web searches, subagent prompts and MCP arguments are checked for identifiers and keys.

**Tampering with the guardrails.** Protected paths cover:
- the policy, baseline and Claude settings
- git hooks and CI workflows
- CODEOWNERS
- the plugin's own install

Changing `core.hooksPath`, `--no-verify` / `-n`, `HUSKY=0` and similar, and turning the plugin off from the CLI are all flagged.

**Config failure.** A broken or invalid repo config falls back to the stricter default policy, not to nothing.

**Policy loosening.** A PR that loosens the policy is checked against the base branch's policy, so an exception can't be added and used in the same PR.

## Known gaps

| Gap | Why | What covers it |
|---|---|---|
| Names, addresses and clinical narrative in free text | Regexes can't tell a patient's name from any other word | Synthetic-data rules, the skill, code review, and keeping real data off developer machines |
| Encoded or packed data (base64, gzip, encrypted, images, PDFs, spreadsheets) | The checker reads text; binary files are judged by type | DATAFILE rules ask or deny by file type; PHI-path rules |
| Identifiers built at runtime ("123" + "-45-" …) | Static checks can't evaluate code | Code review; the same trick is how the tests stay free of real-format values |
| A program that reads data and sends it out (`node sync.js` that fetches) | Only one level of script is inspected, and network calls inside programs aren't traced | Vendor checks on code in the PR; network egress controls on machines that hold PHI |
| A user switches the plugin off in their own settings, or runs `claude --settings '{"disableAllHooks": true}'` | Claude Code lets each user manage their plugins and hooks | Managed settings (below); CI still checks every PR |
| A developer commits with git hooks disabled, or on a machine without the plugin | Local hooks are opt-in by nature | CI on every PR, made a required check with no bypass |
| Someone edits CI or CODEOWNERS to remove the check | Anyone with write access can propose it | CODEOWNERS on `.github/`, branch protection with "require review from code owners" and no bypass for admins |
| Truncating the newest evidence records | A hash chain can't show its own tail was cut | Copy the head hash elsewhere on a schedule (CI summaries, exports) |
| Checker bug or timeout | Hooks fail open by default, so a bug can't stop all work | `fail_closed: true` in the policy; in managed deployments, `onFailure: "block"` on the hook (Claude Code 2.1.295+) |

## Org-wide enforcement

For machines that work on PHI-bearing apps, IT can push Claude Code managed settings that make the guardrails non-optional:

```json
{
  "extraKnownMarketplaces": { "hipaa-guardrails": { "source": { "source": "github", "repo": "freemanlafleur/hipaa-guardrails" } } },
  "enabledPlugins": { "hipaa-guardrails@hipaa-guardrails": true },
  "allowManagedHooksOnly": true
}
```

- A plugin force-enabled in managed settings can't be disabled by a user, project or local setting.
- With `allowManagedHooksOnly`, the guardrails' hooks still run while other hook sources are blocked.
- `disableAllHooks` outside managed settings doesn't stop force-enabled plugins.

This is the strongest setting. The policy owner and IT decide whether to use it.
