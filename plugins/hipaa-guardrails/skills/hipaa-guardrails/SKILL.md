---
name: hipaa-guardrails
description: HIPAA rules for building healthcare apps that handle patient data. Use before writing or reviewing code that touches patient data, logging, test fixtures or seed data, a new vendor SDK or API endpoint, storage, auth, audit logs, secrets or .env files, or an MCP tool that returns patient records; and whenever a guardrails hook blocks or questions an action.
when_to_use: adding a dependency or third-party API, writing tests or seeds, adding logs or error tracking, touching PHI routes, storage buckets, env files, or committing.
---

# HIPAA guardrails for development

These apps hold protected health information (PHI). The rules below keep PHI inside systems covered by a signed Business Associate Agreement (BAA) and out of everything else, including this coding session. They are engineering rules, not legal advice. Where a rule says the policy owner decides, stop and ask instead of choosing.

The repo's own security docs (such as `SECURITY.md` and `CLAUDE.md`) add app-specific rules. Follow both; the stricter one wins.

## What counts as PHI here

Anything that identifies a patient or a person in their household together with anything about their health, care or payment for care. In practice treat all of these as PHI: names, dates of birth, addresses, phone, email, SSN, MRN, insurance and Medicare IDs, photos and video of patients, voice recordings, and any clinical content (notes, diagnoses, labs, medications, assessments, intake answers, transcripts, protocols tied to a person). If a value might be PHI, treat it as PHI.

Safe to record anywhere: opaque ids (a patient UUID is fine for correlation), counts, enum and status values, booleans, error codes, field names.

## The ten rules

1. **BAA vendors only.** PHI may go only to a vendor and service marked `"status": "baa"` in `.hipaa-guardrails.json`. A BAA covers specific services, not a whole company: AWS's BAA covers only HIPAA-eligible services, and many AI APIs need a separate HIPAA setup. `unverified` means ask the policy owner. Never mark a vendor `baa` yourself.
2. **No PHI to AI models without a BAA.** That includes this session. Claude Code, Codex, Copilot and Cursor sessions work on `phi_scope: none` or `synthetic` unless the session runs on a BAA-covered runtime (for example Amazon Bedrock under an AWS BAA, when the repo's policy says so). Don't paste, read, query or summarize real patient records here. MCP tools that return patient data are blocked outside a covered runtime.
3. **No PHI in logs, errors, analytics or trackers.** Log ids, counts and error codes. Never log a whole object, request or response body, row, or form state, and never `JSON.stringify` one into a log line. The same goes for error trackers, analytics events, alert webhooks (Slack, Discord), commit messages, PR bodies, issues and task boards.
4. **Synthetic data only in tests, seeds, fixtures, demos, docs and evals.** Never copy production data down, even "just to reproduce a bug". Use the conventions in `references/synthetic-data.md` and mark fixture files with the word `synthetic-data`. Preview and staging environments use their own database with synthetic data, never production's.
5. **Encrypt in transit and at rest.** https/wss only. Private buckets, server-side encryption, short-lived signed URLs, encrypted backups. No PHI or tokens in URLs or query strings.
6. **Check access on the server, every time.** Authenticate, then authorize the specific action; scope every query to the caller's organization; least privilege for keys and service roles; service-role keys never reach a browser.
7. **Audit PHI access.** Reads and changes of patient data write an append-only audit record: who, what action, which record, when, from where. Never update or delete audit rows. Keep them at least six years.
8. **Secrets stay out of git.** Real values live in the secret manager or an ignored `.env`. Commit only `.env.example` with placeholders. A key that reached git, a log or a chat is rotated, not just deleted.
9. **Minimum necessary.** Select named columns, not `*`, on patient tables. Send a model, vendor or report only the fields the task needs. Don't copy PHI into caches, embeddings, derived tables or search indexes that live outside the BAA-covered store.
10. **If PHI lands somewhere it shouldn't, stop and tell the policy owner** (the `owner` in `.hipaa-guardrails.json`). Don't quietly delete it and move on, and don't paste it anywhere while describing it. Say what kind of data, where, and when. Whether it is a reportable breach is the policy owner's and counsel's call.

## When a hook blocks or questions an action

The hook names a rule id and a file and line, never the value. Fix the cause rather than working around the check:

| Rule id | What to do |
|---|---|
| `PHI-SSN*`, `PHI-MRN`, `PHI-MBI`, `PHI-DOB`, `PHI-MEMBER-ID`, `PHI-GOV-ID`, `PHI-HL7`, `PHI-FHIR-PATIENT`, `PHI-CSV-ROSTER` | Replace with synthetic values (see references). In a command or prompt, describe the case without identifiers. |
| `PHI-EMAIL-FIXTURE`, `PHI-PHONE-FIXTURE` | Use `@example.com` / `.test` emails and `555-01xx` phone numbers. |
| `FIXTURE-NOT-MARKED` | Confirm the data is fake, then add a `synthetic-data` comment or key to the file. |
| `LOG-PHI` | Log ids, counts and `error.code` / `error.message` only. Multi-line calls are checked too. |
| `VENDOR-UNVERIFIED` | Stop. Ask the policy owner whether this vendor has a BAA covering this service. Don't send it data meanwhile. |
| `VENDOR-NO-BAA`, `VENDOR-NO-PHI` | Use a BAA-covered alternative, or keep the vendor to its allowed paths. |
| `SECRET-*`, `ENV-*` | Move the value to the secret manager or an ignored `.env`; rotate it if it was ever committed or shared. Read `.env.example`, not `.env`. |
| `PHI-READ`, `PHI-READ-CONTENT`, `MCP-PHI-TOOL` | The file, folder or tool holds real patient data. Use the synthetic org or synthetic files; real-data work belongs in a covered runtime. If the file is really synthetic, mark it `synthetic-data`. |
| `PHI-EGRESS`, `SECRET-EGRESS` | A web fetch, search, subagent or MCP call carried an identifier or key. Rephrase without it. |
| `DATAFILE-*` | Clinical exchange files and database dumps don't go in repos. Tabular files need to be reference or synthetic data; the policy owner can register an exception for reference data. |
| `GUARD-*`, `CMD-NO-VERIFY`, `CMD-SKIP-HOOKS-ENV` | These protect the guardrails themselves (policy, Claude settings, git hooks, CI, CODEOWNERS). Never edit, move or disable them to get past a check. Tell the person what blocked you and let the policy owner decide. |
| `STORAGE-PUBLIC`, `TLS-PLAIN-HTTP` | Make the bucket private / use https. |
| `CMD-DB-DUMP`, `CMD-GIT-ADD-FORCE` | Dump schema only; don't force-add ignored files. |
| `WAIVER-UNREGISTERED`, `EXCEPTION-EXPIRED` | An inline waiver must name a current, registered exception. See below. |

### Exceptions (waivers)

Some findings are real but acceptable, such as a public code list in a CSV. Those are handled by a registered exception, never by editing a rule:

1. A person proposes it in a PR that changes only `.hipaa-guardrails.json`: an entry in `exceptions` with `id`, `rules`, `paths`, `scope` (`line` or `path`), `reason`, `approver`, `approved_on` and `expires` (at most a year), plus a `policy_version` bump and a `change_log` entry.
2. The policy owner approves it through CODEOWNERS review. CI fails a policy change without the version bump and approver.
3. Code then references it inline as `phi-ok: EXC-0007` (line scope), or it covers its paths outright (path scope).

Never add or widen an exception yourself, never write an inline waiver that names no registered exception, and never add one in the same PR as the code it would excuse: a PR that loosens the policy is checked against the base branch's policy. Rules about real patient data reaching a session or tool, and rules that protect the guardrails, can't be excepted at all.

## Before you finish a change

- New dependency or endpoint? Check its vendor status in `.hipaa-guardrails.json`.
- New PHI route or tool? Auth, permission check, org scoping, audit record.
- New logs? PHI-free.
- New tests or seeds? Synthetic and marked.
- Run `/hipaa-guardrails:hipaa-check` (or `python3 <plugin>/scripts/guard.py scan --diff origin/main`).
- Changed `.hipaa-guardrails.json`? Bump `policy_version`, add a `change_log` entry, and leave the approver to the policy owner.

See `references/vendor-review.md` for adding a vendor and `references/synthetic-data.md` for test data conventions.
