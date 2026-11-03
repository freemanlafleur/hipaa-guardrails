# Review and coding rules for agents (Codex, Claude, Copilot)

This app handles protected health information (PHI). In every review and change, apply the HIPAA guardrails. Flag as P1 any of:

1. A new third-party SDK, API host or webhook that isn't marked `"status": "baa"` in `.hipaa-guardrails.json` and could receive app data.
2. PHI or whole objects (patient, note, row, request or response body, form state) in logs, errors, analytics, error trackers, alerts, commit messages or PR text. Ids, counts and error codes are fine.
3. Real-looking personal data in tests, seeds, fixtures, demos or docs. Test data must be synthetic: `@example.com` emails, `555-01xx` phones, SSNs starting with 9, ids prefixed `TEST-`/`SYN-`, and the file marked `synthetic-data`.
4. A route or tool that reads or changes patient data without a server-side auth check, a permission check, organization scoping and an audit record.
5. Public storage, plain http, PHI or tokens in URLs or query strings.
6. Secrets in code, or a committed `.env` file.
7. `select *` or whole-record payloads where a few fields would do.
8. A `phi-ok:` marker that doesn't name a registered, unexpired exception in `.hipaa-guardrails.json`, or a change that adds an exception or loosens the policy without the policy owner's approval.

Never quote a suspected identifier or secret in a review comment; point to the file and line.
The full rules live in the hipaa-guardrails Claude Code plugin's skill. CI runs the same checker (`HIPAA guardrails` check).
