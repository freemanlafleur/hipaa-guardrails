# Evidence trail

Every decision the guardrails make leaves one JSON line. That includes:
- hook decisions, both allowed and blocked
- prompt checks
- pre-commit checks
- CI runs
- full scans

The log is meant to answer an auditor's questions. Which controls ran, when, under which policy version, what did they catch, and which exceptions were used?

## What a record holds

```json
{
  "v": 1, "ts": "2026-11-02T17:41:48.303Z",
  "event": "hook | userprompt | precommit | ci | scan | hook-error",
  "tool": "Write", "decision": "allow | warn | ask | deny | block | pass | fail",
  "mode": "enforce", "covered_runtime": false,
  "findings": [{"rule": "LOG-PHI", "action": "deny", "path": "src/r.ts", "line": 1, "exception": "EXC-0007"}],
  "policy": {"version": "1.2.0", "sha256": "...", "default_sha256": "...", "schema": 2},
  "plugin_version": "0.2.0",
  "repo": {"name": "my-app", "commit": "...", "branch": "...", "remote": "https://github.com/..."},
  "actor": "dev@example.com | github:login", "session_id": "...",
  "policy_change": {"from": "1.1.0", "to": "1.2.0", "approver": "...", "loosened": ["..."]},
  "prev": "<hash of the previous record>", "hash": "<sha256 of this record without its hash>"
}
```

**Never stored:** file contents, prompts, shell commands, URLs or matched values.

**Hashed paths:** for rules about PHI paths (PHI-READ*, DATAFILE-*), the file path is replaced by a short SHA-256, because file names can carry patient names.

**Remote URLs:** credentials embedded in a remote URL are stripped.

## Where it lives

| Context | Location |
|---|---|
| Developer machine (hooks and pre-commit) | `${CLAUDE_CONFIG_DIR:-~/.claude}/hipaa-guardrails/evidence/<repo>-<id>/YYYY-MM.jsonl` |
| CI | `$HIPAA_GUARDRAILS_EVIDENCE_DIR` (the templates use `runner.temp`), uploaded as a build artifact per run |
| Override | `HIPAA_GUARDRAILS_EVIDENCE_DIR`, or `evidence.dir` in the policy |

`evidence.log_allowed: false` stops recording clean allow decisions. Recording them is the default, because an auditor sampling "was every write checked?" needs the allows too.

## Tamper evidence

- Each record carries the hash of the one before it.
- The first record of a new month links to the last record of the previous month.
- Writes take a file lock.

`guard.py evidence verify` recomputes the chain. It reports any record that was edited, removed or reordered, and any missing month file.

A chain can't show that its newest records were cut off the end. To close that gap, copy the head hash somewhere else on a schedule:
- `guard.py evidence head` prints it.
- CI writes it to the step summary.
- The weekly export carries it.

Every CI run records its hash in the run's summary, which GitHub keeps with the run.

## Commands

```
guard.py evidence path                         # where this repo's log is
guard.py evidence verify                       # exit 1 if the chain is broken
guard.py evidence report [--since 2026-10-01] [--format md|json]
guard.py evidence export --out DIR [--since …] # bundle for an auditor or Vanta
```

The export bundle contains:
- the month files
- `report.md` and `report.json`
- the merged policy and the repo policy as they stand
- `MANIFEST.sha256`, so a reviewer can check nothing changed (`sha256sum -c MANIFEST.sha256`)

## Retention

HIPAA requires security documentation to be kept six years from creation or last effective date (45 CFR 164.316(b)(2)(i)). GitHub keeps Actions artifacts at most 90 days by default and at most 400 days for private repositories, so artifacts alone don't meet that. Options, for the policy owner to choose:

1. A scheduled job copies CI evidence and a monthly export to an S3 bucket with Object Lock (compliance mode, six years). This needs an AWS account under your organization's BAA if the evidence is treated as sensitive; by design it holds no PHI.
2. Upload the monthly export to Vanta as a document through the Vanta API (`POST /v1/documents/{id}/uploads`, then `/submit`), mapped to the change-management and secure-development controls.
3. Both. Vanta for the audit window, S3 for the six years.

## How an auditor would use it (SOC 2 Type II)

A Type II audit tests whether controls operated over a window, usually 3 to 12 months. For this plugin the population is every pull request merged in the window. The auditor samples PRs and, for each, asks:
- Did the guardrails check run?
- Under which policy version?
- What did it find?
- Was any exception registered and approved before use?
- If the policy changed, who approved it?

The CI artifact, step summary, the policy's change_log and git history answer each of those. Vanta's GitHub integration separately evidences branch protection and code review. Developer-machine logs show the preventive layer (what was stopped before it reached a commit). Export them monthly if the policy owner wants them in the audit.
