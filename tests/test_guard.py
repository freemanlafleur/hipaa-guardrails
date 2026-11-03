"""Tests for guard.py. All data here is synthetic-data; identifier-shaped values are
assembled at runtime so this file never holds a real-format value as a literal.

Run: python3 -m unittest discover -s tests -v
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "..", "plugins", "hipaa-guardrails", "scripts", "guard.py")

FAKE_SSN = "123" + "-45-" + "6789"          # valid format, so it must be caught
SYNTH_SSN = "900" + "-12-" + "3456"          # 9xx area: never issued, allowed
TODAY = datetime.date.today().isoformat()
SOON = (datetime.date.today() + datetime.timedelta(days=180)).isoformat()
EVIDENCE_DIR = tempfile.mkdtemp(prefix="hg-evidence-")
FAKE_MRN_LINE = 'mrn: "' + "A1" + "234567" + '"'


def run(args, stdin=None, cwd=None, env=None):
    e = dict(os.environ)
    e.pop("CLAUDE_CODE_USE_BEDROCK", None)
    e.setdefault("HIPAA_GUARDRAILS_EVIDENCE_DIR", EVIDENCE_DIR)
    if env:
        e.update(env)
    r = subprocess.run([sys.executable, GUARD] + args, input=stdin, cwd=cwd, env=e,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    return r


class Repo:
    def __init__(self, policy=None):
        self.dir = tempfile.mkdtemp(prefix="hg-test-")
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.dir, check=True)
        subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=self.dir, check=True)
        subprocess.run(["git", "config", "user.name", "Dev"], cwd=self.dir, check=True)
        self.write(".gitignore", ".env\n.env.local\n")
        if policy is not None:
            self.write(".hipaa-guardrails.json", json.dumps(policy))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")

    def write(self, path, text):
        p = os.path.join(self.dir, path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def git(self, *args):
        subprocess.run(["git"] + list(args), cwd=self.dir, check=True, stdout=subprocess.DEVNULL)

    def hook(self, tool, tool_input, env=None):
        payload = {"hook_event_name": "PreToolUse", "cwd": self.dir, "tool_name": tool, "tool_input": tool_input}
        r = run(["hook", "pretooluse"], stdin=json.dumps(payload), cwd=self.dir, env=env)
        if not r.stdout.strip():
            return None, ""
        out = json.loads(r.stdout)
        hso = out.get("hookSpecificOutput", {})
        return hso.get("permissionDecision", "message"), hso.get("permissionDecisionReason", out.get("systemMessage", ""))

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class HookTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo({"vendors": {"posthog": {"status": "no_phi", "allowed_paths": ["src/marketing/**"]},
                                      "aws": {"status": "baa"},
                                      "openai-direct": {"status": "no_baa"}},
                          "phi_mcp_tools": ["^mcp__EHR__(get_patient_.*|search_patients)$"]})

    def tearDown(self):
        self.repo.close()

    def test_clean_write_passes(self):
        d, _ = self.repo.hook("Write", {"file_path": "src/a.ts", "content": "export const x = 1;\n"})
        self.assertIsNone(d)

    def test_ssn_in_source_denied_and_value_hidden(self):
        d, why = self.repo.hook("Write", {"file_path": "src/a.ts", "content": "const s = '%s';\n" % FAKE_SSN})
        self.assertEqual(d, "deny")
        self.assertIn("PHI-SSN", why)
        self.assertNotIn(FAKE_SSN, why)

    def test_synthetic_ssn_allowed(self):
        d, _ = self.repo.hook("Write", {"file_path": "src/a.ts", "content": "const s = '%s';\n" % SYNTH_SSN})
        self.assertIsNone(d)

    def test_mrn_literal_denied(self):
        d, why = self.repo.hook("Edit", {"file_path": "src/a.ts", "old_string": "x", "new_string": FAKE_MRN_LINE})
        self.assertEqual(d, "deny")
        self.assertIn("PHI-MRN", why)

    def test_mrn_variable_not_flagged(self):
        d, _ = self.repo.hook("Edit", {"file_path": "src/a.ts", "old_string": "x", "new_string": "mrn: patient.mrn,"})
        self.assertIsNone(d)

    def test_log_whole_patient_denied(self):
        d, why = self.repo.hook("Write", {"file_path": "src/api/route.ts",
                                          "content": "console.error('[patients:save] failed', { patient, note });\n"})
        self.assertEqual(d, "deny")
        self.assertIn("LOG-PHI", why)

    def test_log_ids_only_passes(self):
        d, _ = self.repo.hook("Write", {"file_path": "src/api/route.ts",
                                        "content": "console.error('[patients:saveNote] note save failed', { patientId, noteId, code: error?.code });\n"})
        self.assertIsNone(d)

    def test_log_waiver_needs_registered_exception(self):
        d, why = self.repo.hook("Write", {"file_path": "src/api/route.ts",
                                          "content": "console.log(JSON.stringify(stats)); // phi-ok: aggregate counts only\n"})
        self.assertEqual(d, "deny")
        self.assertIn("WAIVER-UNREGISTERED", why)

    def test_log_waiver_with_registered_exception(self):
        pol = json.loads(open(os.path.join(self.repo.dir, ".hipaa-guardrails.json")).read())
        pol["exceptions"] = [{"id": "EXC-0001", "rules": ["LOG-PHI"], "paths": ["src/api/**"], "reason": "aggregate counts",
                              "approver": "owner@example.com", "approved_on": TODAY, "expires": SOON}]
        self.repo.write(".hipaa-guardrails.json", json.dumps(pol))
        d, _ = self.repo.hook("Write", {"file_path": "src/api/route.ts",
                                        "content": "console.log(JSON.stringify(stats)); // phi-ok: EXC-0001\n"})
        self.assertIsNone(d)

    def test_python_print_body(self):
        d, _ = self.repo.hook("Write", {"file_path": "worker/sync.py", "content": "print(f\"row {row}\")\n"})
        self.assertEqual(d, "deny")

    def test_vendor_no_baa_denied(self):
        d, why = self.repo.hook("Write", {"file_path": "src/ai.ts", "content": "import OpenAI from 'openai';\n"})
        self.assertEqual(d, "deny")
        self.assertIn("VENDOR-NO-BAA", why)

    def test_vendor_baa_allowed(self):
        d, _ = self.repo.hook("Write", {"file_path": "src/s3.ts", "content": "import { S3Client } from '@aws-sdk/client-s3';\n"})
        self.assertIsNone(d)

    def test_vendor_unverified_asks(self):
        d, why = self.repo.hook("Write", {"file_path": "src/err.ts", "content": "import * as Sentry from '@sentry/nextjs';\n"})
        self.assertEqual(d, "ask")
        self.assertIn("VENDOR-UNVERIFIED", why)

    def test_vendor_host_unverified(self):
        d, _ = self.repo.hook("Write", {"file_path": "src/alert.ts", "content": "await fetch('https://hooks.slack.com/services/T0/B0/x', {method:'POST'});\n"})
        self.assertEqual(d, "ask")

    def test_vendor_no_phi_outside_allowed_path(self):
        d, why = self.repo.hook("Write", {"file_path": "src/app/chart.tsx", "content": "import posthog from 'posthog-js';\n"})
        self.assertEqual(d, "deny")
        self.assertIn("VENDOR-NO-PHI", why)

    def test_vendor_no_phi_inside_allowed_path(self):
        d, _ = self.repo.hook("Write", {"file_path": "src/marketing/analytics.ts", "content": "import posthog from 'posthog-js';\n"})
        self.assertIsNone(d)

    def test_existing_vendor_import_not_reflagged_on_edit(self):
        d, _ = self.repo.hook("Edit", {"file_path": "src/err.ts",
                                       "old_string": "import * as Sentry from '@sentry/nextjs';\nconst a = 1;",
                                       "new_string": "import * as Sentry from '@sentry/nextjs';\nconst a = 2;"})
        self.assertIsNone(d)

    def test_package_json_dependency(self):
        d, _ = self.repo.hook("Edit", {"file_path": "package.json", "old_string": '"zod": "^3"',
                                       "new_string": '"zod": "^3",\n    "openai": "^4"'})
        self.assertEqual(d, "deny")

    def test_secret_denied_even_with_waiver(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        d, why = self.repo.hook("Write", {"file_path": "src/cfg.ts", "content": "const k = '%s'; // phi-ok: test\n" % key})
        self.assertEqual(d, "deny")
        self.assertNotIn(key, why)

    def test_env_file_not_ignored_denied(self):
        d, why = self.repo.hook("Write", {"file_path": ".env.production", "content": "X=1\n"})
        self.assertEqual(d, "deny")
        self.assertIn("ENV-NOT-IGNORED", why)

    def test_env_file_ignored_ok(self):
        d, _ = self.repo.hook("Write", {"file_path": ".env.local", "content": "X=1\n"})
        self.assertIsNone(d)

    def test_fixture_contact_and_marker(self):
        content = '[{"first_name": "Jordan", "email": "jordan@gmail.com", "phone": "312-867-5309"}]\n'
        d, why = self.repo.hook("Write", {"file_path": "tests/fixtures/patients.json", "content": content})
        self.assertEqual(d, "ask")
        for rule in ("PHI-EMAIL-FIXTURE", "PHI-PHONE-FIXTURE", "FIXTURE-NOT-MARKED"):
            self.assertIn(rule, why)

    def test_fixture_synthetic_ok(self):
        content = '{"_meta": "synthetic-data", "patients": [{"first_name": "Jordan", "email": "jordan@example.com", "phone": "312-555-0142"}]}\n'
        d, _ = self.repo.hook("Write", {"file_path": "tests/fixtures/patients.json", "content": content})
        self.assertIsNone(d)

    def test_read_phi_path_denied(self):
        d, _ = self.repo.hook("Read", {"file_path": os.path.join(self.repo.dir, "exports", "march.csv")})
        self.assertEqual(d, "deny")

    def test_read_phi_path_allowed_on_covered_bedrock(self):
        self.repo.write(".hipaa-guardrails.json", json.dumps({"runtime": {"bedrock_is_baa_covered": True}}))
        d, _ = self.repo.hook("Read", {"file_path": os.path.join(self.repo.dir, "exports", "march.csv")},
                              env={"CLAUDE_CODE_USE_BEDROCK": "1"})
        self.assertIsNone(d)

    def test_mcp_phi_tool_denied(self):
        d, _ = self.repo.hook("mcp__EHR__get_patient_context", {"patient_id": "x"})
        self.assertEqual(d, "deny")

    def test_mcp_other_tool_ok(self):
        d, _ = self.repo.hook("mcp__EHR__list_templates", {})
        self.assertIsNone(d)

    def test_public_bucket_denied(self):
        d, _ = self.repo.hook("Write", {"file_path": "src/s3.ts", "content": "await s3.putObject({ ACL: 'public-read' });\n"})
        self.assertEqual(d, "deny")

    def test_plain_http_is_warning_only(self):
        d, why = self.repo.hook("Write", {"file_path": "src/x.ts", "content": "const u = 'http://api.partner.io/v1';\n"})
        self.assertEqual(d, "message")
        self.assertIn("TLS-PLAIN-HTTP", why)

    def test_bash_no_verify_denied(self):
        d, _ = self.repo.hook("Bash", {"command": "git commit --no-verify -m wip"})
        self.assertEqual(d, "deny")

    def test_bash_ssn_in_command_denied(self):
        d, _ = self.repo.hook("Bash", {"command": "psql -c \"select * from patients where ssn='%s'\"" % FAKE_SSN})
        self.assertEqual(d, "deny")

    def test_bash_git_add_env_denied(self):
        d, _ = self.repo.hook("Bash", {"command": "git add .env src/"})
        self.assertEqual(d, "deny")

    def test_bash_curl_post_to_no_baa_vendor(self):
        d, _ = self.repo.hook("Bash", {"command": "curl -X POST https://api.openai.com/v1/chat/completions -d @note.json"})
        self.assertEqual(d, "deny")

    def test_bash_commit_checks_staged(self):
        self.repo.write("src/leak.ts", "console.log(JSON.stringify(req.body));\n")
        self.repo.git("add", "src/leak.ts")
        d, why = self.repo.hook("Bash", {"command": "git commit -m 'add route'"})
        self.assertEqual(d, "deny")
        self.assertIn("LOG-PHI", why)

    def test_bash_commit_clean_passes(self):
        self.repo.write("src/ok.ts", "export const ok = true;\n")
        self.repo.git("add", "src/ok.ts")
        d, _ = self.repo.hook("Bash", {"command": "git commit -m 'add ok'"})
        self.assertIsNone(d)

    def test_db_dump_asks(self):
        d, _ = self.repo.hook("Bash", {"command": "pg_dump $DATABASE_URL > dump.sql"})
        self.assertEqual(d, "ask")

    def test_warn_mode_never_blocks(self):
        self.repo.write(".hipaa-guardrails.json", json.dumps({"mode": "warn"}))
        d, why = self.repo.hook("Write", {"file_path": "src/a.ts", "content": "const s = '%s';\n" % FAKE_SSN})
        self.assertEqual(d, "message")
        self.assertIn("PHI-SSN", why)


    def test_warn_mode_still_blocks_phi_mcp_and_secrets(self):
        self.repo.write(".hipaa-guardrails.json", json.dumps({"mode": "warn", "phi_mcp_tools": ["^mcp__EHR__get_patient_"]}))
        d, _ = self.repo.hook("mcp__EHR__get_patient_context", {})
        self.assertEqual(d, "deny")
        d, _ = self.repo.hook("Write", {"file_path": "src/k.ts", "content": "const k = '%s';\n" % ("AKIA" + "ABCDEFGHIJKLMNOP")})
        self.assertEqual(d, "deny")


class PromptTests(unittest.TestCase):
    def test_prompt_with_ssn_blocked(self):
        repo = Repo({})
        try:
            r = run(["hook", "userprompt"], stdin=json.dumps({"cwd": repo.dir, "prompt": "patient ssn %s keeps failing" % FAKE_SSN}), cwd=repo.dir)
            out = json.loads(r.stdout)
            self.assertEqual(out["decision"], "block")
            self.assertNotIn(FAKE_SSN, out["reason"])
            r = run(["hook", "userprompt"], stdin=json.dumps({"cwd": repo.dir, "prompt": "fix the intake form layout"}), cwd=repo.dir)
            self.assertEqual(r.stdout.strip(), "")
        finally:
            repo.close()


class CITests(unittest.TestCase):
    def test_scan_diff_fails_on_deny_and_lists_waivers(self):
        repo = Repo({})
        try:
            pol = {"exceptions": [{"id": "EXC-0002", "rules": ["LOG-PHI"], "paths": ["src/a.ts"], "reason": "counts only",
                                   "approver": "owner@example.com", "approved_on": TODAY, "expires": SOON}]}
            repo.write(".hipaa-guardrails.json", json.dumps(pol))
            repo.git("add", "-A")
            repo.git("commit", "-q", "-m", "policy")
            repo.write("src/a.ts", "console.log(patient);\nconsole.log(rows); // phi-ok: EXC-0002\n")
            repo.git("checkout", "-q", "-b", "feature")
            repo.git("add", "-A")
            repo.git("commit", "-q", "-m", "x")
            r = run(["scan", "--diff", "main", "--github"], cwd=repo.dir)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("::error file=src/a.ts,line=1", r.stdout)
            self.assertIn("exception EXC-0002", r.stdout)
            self.assertNotIn("line=2,title=HIPAA guardrails LOG-PHI", r.stdout)
        finally:
            repo.close()

    def test_scan_diff_flags_tracked_env(self):
        repo = Repo({})
        try:
            repo.write(".env.production", "X=1\n")
            repo.git("checkout", "-q", "-b", "feature")
            repo.git("add", "-f", ".env.production")
            repo.git("commit", "-q", "-m", "x")
            r = run(["scan", "--diff", "main"], cwd=repo.dir)
            self.assertEqual(r.returncode, 1)
            self.assertIn("ENV-TRACKED", r.stdout)
        finally:
            repo.close()

    def test_scan_clean_passes(self):
        repo = Repo({})
        try:
            repo.write("src/a.ts", "export const a = 1;\n")
            repo.git("checkout", "-q", "-b", "feature")
            repo.git("add", "-A")
            repo.git("commit", "-q", "-m", "x")
            r = run(["scan", "--diff", "main"], cwd=repo.dir)
            self.assertEqual(r.returncode, 0, r.stdout)
        finally:
            repo.close()


if __name__ == "__main__":
    unittest.main()
