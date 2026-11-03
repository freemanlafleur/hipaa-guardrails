# Control matrix: HIPAA guardrails plugin 0.2.0

Draft, Nov 2 2026. Maps each guardrail to the HIPAA Security and Privacy Rule provisions and the SOC 2 Trust Services Criteria it supports, and to the evidence it leaves. It is an engineering mapping for planning and audit preparation, not a legal opinion. Whether these controls satisfy a requirement for your organization is for the policy owner, the auditor and counsel to decide.

Sources:
- HIPAA: 45 CFR Part 164 on eCFR, Title 45 current as of Oct 23 2026.
- SOC 2: 2017 Trust Services Criteria with revised points of focus (2022). AICPA gates the official PDF behind a login, so the criteria wording used for this mapping came from a secondary copy. Confirm it against the official document before an audit.

## Scope

**In scope:** the software development workflow, on any machine or CI runner where the plugin or the CI check runs:
- AI coding sessions (Claude Code), including prompts, file reads, edits, shell commands, web fetches, subagents and MCP tools
- git commits
- pull requests

The control objective: patient data never enters source code, tests, fixtures, logs, AI sessions or third-party tools that aren't covered by a BAA, and the rules that enforce this can't be changed quietly.

**Out of scope** (each needs its own control): the production system itself, including
- encryption at rest
- application access control
- PHI access audit logging
- backups and disaster recovery
- incident response
- risk analysis
- workforce training records
- BAAs themselves
- vulnerability and patch management, which needs its own process

These guardrails support those controls and don't replace them.

## Matrix

| Id | Control | Enforced by (rule ids) | Where | HIPAA provisions supported | SOC 2 criteria supported | Evidence |
|---|---|---|---|---|---|---|
| HG-01 | Real patient identifiers never appear in code, tests, fixtures, docs, commit text or commands; test data is synthetic and marked | PHI-SSN, PHI-SSN-LABELED, PHI-SSN-SPACED, PHI-MRN, PHI-MBI, PHI-DOB, PHI-MEMBER-ID, PHI-GOV-ID, PHI-HL7, PHI-FHIR-PATIENT, PHI-CSV-ROSTER, PHI-EMAIL/PHONE-FIXTURE, FIXTURE-NOT-MARKED | Hook, pre-commit, CI | 164.502(b) and 164.514(d) minimum necessary; 164.514(a)-(b) de-identification (synthetic data used in place of PHI); 164.308(a)(1)(ii)(B) risk management | C1.1; CC6.7 | Hook, pre-commit and CI records with rule, file and line; CI annotations on the PR |
| HG-02 | Patient data doesn't reach an AI model session, subagent, web service or MCP server without a BAA | PHI-READ, PHI-READ-CONTENT, MCP-PHI-TOOL, PHI-EGRESS (prompts, WebFetch, WebSearch, Agent, MCP arguments) | Hook | 164.502(e) and 164.308(b)(1) business associate contracts; 164.314(a) contract terms; 164.312(a)(1) access control; 164.502(b) minimum necessary | CC6.1; CC6.7; CC9.2; C1.1 | Hook and prompt records (paths hashed for PHI-path rules) |
| HG-03 | Code only sends data to vendors whose BAA status the policy owner has recorded; unverified vendors are questioned, no-BAA vendors blocked, no-PHI vendors kept to allowed paths | VENDOR-UNVERIFIED, VENDOR-NO-BAA, VENDOR-NO-PHI (imports, dependencies, hosts, shell uploads) | Hook, pre-commit, CI | 164.308(b)(1) and (b)(3); 164.314(a)(1)-(2); 164.502(e) | CC9.2; CC3.2 | Vendor catalog with statuses and notes in the versioned policy; findings in records |
| HG-04 | Logs, error trackers and analytics carry ids, counts and codes, never patient objects or fields | LOG-PHI (single and multi-line calls) | Hook, pre-commit, CI | 164.502(b) minimum necessary; 164.308(a)(1)(ii)(B) | C1.1; CC6.7 | Records; CI annotations |
| HG-05 | Secrets stay out of git and out of AI sessions | SECRET-*, SECRET-EGRESS, ENV-NOT-IGNORED, ENV-STAGED, ENV-TRACKED, ENV-READ | Hook, pre-commit, CI | 164.312(a)(1) access control; 164.312(d) person or entity authentication; 164.308(a)(5)(ii)(D) password management | CC6.1 | Records |
| HG-06 | Storage isn't public and transport is encrypted; app-specific access patterns are enforced (per-repo custom rules) | STORAGE-PUBLIC, TLS-PLAIN-HTTP, CS-* custom rules | Hook, pre-commit, CI | 164.312(a)(1); 164.312(a)(2)(iv) encryption and decryption; 164.312(e)(1) transmission security | CC6.1; CC6.6; CC6.7 | Records |
| HG-07 | Clinical exchange files, database dumps and unreviewed tabular data don't enter repositories | DATAFILE-CLINICAL, DATAFILE-DUMP, DATAFILE-TABULAR, CMD-DB-DUMP | Hook, pre-commit, CI | 164.310(d)(1) device and media controls, (d)(2)(iii) accountability; 164.308(a)(1)(ii)(B) | C1.1; C1.2; CC6.7 | Records |
| HG-08 | The guardrails can't be switched off or edited from inside an AI session or a commit without a person's decision | GUARD-CONFIG, GUARD-HOOKSPATH, GUARD-PLUGIN-OFF, GUARD-PROTECTED-FILE, GUARD-HOOK-NOT-EXECUTABLE, CMD-NO-VERIFY, CMD-SKIP-HOOKS-ENV, CONFIG-INVALID (broken config falls back to the strict default) | Hook, CI | 164.308(a)(1)(ii)(B); 164.308(a)(8) evaluation | CC5.2; CC8.1 | Records of asks and denials; CODEOWNERS review on protected paths |
| HG-09 | Policy changes are versioned, approved and reviewed; a change that loosens the policy is listed and doesn't take effect until merged | POLICY-CHANGE-UNRECORDED, POLICY-LOOSENED, POLICY-BASE-USED, CONFIG-UNVERSIONED, CODEOWNERS on the policy file | CI | 164.316(a) policies and procedures; 164.316(b)(1) documentation; 164.316(b)(2)(iii) updates; 164.308(a)(2) assigned security responsibility | CC8.1; CC3.4; CC5.3 | change_log entries (version, date, approver, summary); git history; CI records with from, to, approver and loosenings |
| HG-10 | Exceptions are registered with an owner, reason and expiry of at most a year, and can't cover the rules about real PHI reaching sessions or tools | WAIVER-UNREGISTERED, EXCEPTION-EXPIRED, EXCEPTION-EXPIRING, never_excepted | Hook, pre-commit, CI | 164.316(b)(1); 164.308(a)(1)(ii)(B) | CC5.3; CC3.2 | exceptions list in the versioned policy; each record names the exception that covered a finding |
| HG-11 | Every guardrail decision leaves a tamper-evident record with no patient data in it | Evidence log (hash-chained JSONL), `evidence verify/report/export`, CI artifact and step summary | Hook, pre-commit, CI | 164.308(a)(1)(ii)(D) information system activity review; 164.316(b)(2)(i) six-year retention (needs durable storage; see EVIDENCE.md) | CC4.1; CC7.2; CC2.1 | The log itself, its verification, exported bundles with a SHA-256 manifest |
| HG-12 | People and AI agents get the rules where they work | Skill (loaded by Claude Code), AGENTS.md (Codex reviews), CLAUDE.md snippet, hook messages that name the rule | Session, PR review | 164.308(a)(5)(i) security awareness and training, (a)(5)(ii)(A) security reminders; 164.316(b)(2)(ii) availability | CC5.3; CC2.1 | Files in the repo and plugin; hook messages recorded by rule id |

## Decisions that belong to people

The plugin enforces whatever the policy says. These inputs come from people, and the matrix depends on them:

| Decision | Owner | Why it matters |
|---|---|---|
| Each vendor's status (baa, no_phi, no_baa) and which services a BAA covers | Policy owner, with the signed agreement | HG-02, HG-03 rest on it. The plugin never marks a vendor `baa` by itself. |
| Whether a model runtime (for example Amazon Bedrock under the organization's AWS BAA) counts as covered for PHI | Policy owner and counsel | Turns on `runtime.bedrock_is_baa_covered`, which lets covered sessions read PHI paths and call patient-data MCP tools. |
| Who the policy owner and CODEOWNERS are | Leadership | HG-08 to HG-10 need a named approver who isn't the change's author. |
| Moving each repo from warn to enforce mode | Policy owner | Warn mode still blocks the always-enforced rules, but not the rest. |
| Where evidence is kept for six years (S3 with Object Lock, Vanta, both) | Policy owner | GitHub keeps artifacts at most 400 days for private repos. |
| Whether a given leak is a reportable breach | Counsel | The plugin and its records describe what happened; they don't decide that. |
| Org-wide enforcement through Claude Code managed settings | IT and policy owner | Makes the plugin impossible to switch off per user (see THREAT-MODEL.md). |

## HIPAA Security Rule changes

HHS proposed a major update to the Security Rule (RIN 0945-AA22, published Jan 6 2025). As of Nov 2026 it is still pending. The Unified Agenda lists it as a long-term action with a final action shown for July 2027, and HHS says the current rule remains in effect.

If it's adopted as proposed, it would remove the required/addressable split and require:
- written documentation
- an asset inventory
- encryption
- MFA
- vulnerability scans every 6 months
- penetration tests every 12 months
- annual compliance audits

This matrix cites the current rule only. Proposed paragraph numbers would change, so don't mix the two.
