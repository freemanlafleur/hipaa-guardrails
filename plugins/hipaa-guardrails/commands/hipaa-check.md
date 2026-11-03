---
description: Run the HIPAA guardrails over this branch's changes (same check as CI) and fix what it finds
argument-hint: "[base branch, default origin/main]"
allowed-tools: Bash(python3:*), Bash(git diff:*), Bash(git fetch:*)
---

Run the HIPAA guardrails checker against the changes on this branch. The base is `$ARGUMENTS` if one was given, otherwise `origin/main`:

```
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard.py" scan --diff <base>
```

Then, for each finding:
- Fix it in the code, following the hipaa-guardrails skill (synthetic data, PHI-free logs, BAA-covered vendors only, no secrets in git).
- Never print, quote or copy the flagged value into chat, a commit message or a PR; refer to it by file and line.
- A VENDOR-UNVERIFIED finding is a question for the policy owner, not something to fix by renaming. List those separately at the end.
- Don't add an exception or an inline `phi-ok:` waiver to silence a finding, and don't edit the policy, hooks, settings or CI. If you think a finding is a false positive, say why and leave the decision to the policy owner.
- If the output lists POLICY-LOOSENED or POLICY-CHANGE-UNRECORDED, report them; they need the policy owner's approval.

Also run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/guard.py" validate-config` and include any CONFIG or EXCEPTION findings.

Finish with a short list: fixed, still open, and questions for a human.
