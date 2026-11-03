# Adding or changing a vendor

Every third party that could receive data from an app is listed under `vendors` in the policy, with packages and hosts so the checker can spot it. The repo's `.hipaa-guardrails.json` sets each vendor's status for that app.

## Statuses

| Status | Meaning | Checker |
|---|---|---|
| `baa` | A signed BAA covers the specific services this app uses, and they are configured as the BAA requires | Allowed |
| `no_phi` | Allowed, but by design never receives PHI (payments, marketing analytics). Optional `allowed_paths` limits where it may be imported | Blocked outside `allowed_paths` |
| `no_baa` | Must not be used in this app | Blocked |
| `unverified` | Nobody has confirmed yet | Asks a human (hooks); warning (CI) |

Only the policy owner sets a status, after checking the agreement. Claude never flips a status, even when a vendor's website says it is "HIPAA compliant". A marketing page isn't a signed BAA.

## What to record for a `baa` vendor

In the vendor's entry, add a `notes` string with: the agreement (and date), which services it covers, and any configuration it requires. Examples of configuration that a BAA often depends on:

- AWS: only HIPAA-eligible services, in the account that accepted the BAA.
- Azure OpenAI: the Microsoft BAA, plus abuse-monitoring or retention settings if the agreement calls for them.
- Supabase: the HIPAA add-on on the specific project; not every project in the org.
- Anthropic or OpenAI APIs: the HIPAA-ready / zero-retention setup on the specific org or workspace.

## Adding a new vendor

1. Add an entry under `vendors` in the repo's `.hipaa-guardrails.json` with `packages`, `py_modules` and `domains`, and `"status": "unverified"`.
2. Ask the policy owner for the status. Until then, don't send it any data from PHI code paths.
3. If it will never see PHI, `no_phi` with `allowed_paths` keeps it fenced in.

Model providers used only by a developer's own tools (this session, Codex review) aren't app vendors, but rule 2 still applies: no real PHI in them unless the runtime is BAA-covered.
