"""Adversarial and audit tests for guard.py v0.2. All data here is synthetic-data:
identifier-shaped values are assembled at runtime, and no file holds one as a literal.

Run: python3 -m unittest discover -s tests -v
"""
import glob
import json
import os
import subprocess
import tempfile
import time
import unittest
from datetime import date, timedelta

from test_guard import FAKE_SSN, SYNTH_SSN, GUARD, Repo, run

FAKE_SSN_DIGITS = FAKE_SSN.replace("-", "")
FAKE_MRN_VALUE = "A1" + "234567"
OWNER = "owner@example.com"


TODAY = date.today().isoformat()
SOON = (date.today() + timedelta(days=180)).isoformat()


def exc(eid, rules, paths, scope="line", expires=SOON, **kw):
    e = {"id": eid, "rules": rules, "paths": paths, "scope": scope, "reason": "test", "approver": OWNER,
         "approved_on": TODAY, "expires": expires}
    e.update(kw)
    return e


def assert_no_leak(tc, *blobs):
    for b in blobs:
        for v in (FAKE_SSN, FAKE_SSN_DIGITS, FAKE_MRN_VALUE):
            tc.assertNotIn(v, b or "")


class Base(unittest.TestCase):
    policy = {}

    def setUp(self):
        self.ev = tempfile.mkdtemp(prefix="hg-ev-")
        self.repo = Repo(self.policy)

    def tearDown(self):
        self.repo.close()

    def hook(self, tool, tin, env=None):
        e = {"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev}
        e.update(env or {})
        return self.repo.hook(tool, tin, env=e)

    def bash(self, cmd, env=None):
        return self.hook("Bash", {"command": cmd}, env)

    def evidence_text(self):
        return "".join(open(p).read() for p in glob.glob(os.path.join(self.ev, "*.jsonl")))


class UnicodeEvasionTests(Base):
    def write(self, value):
        return self.hook("Write", {"file_path": "src/a.ts", "content": "const s = '%s';\n" % value})

    def test_zero_width_inside_ssn(self):
        self.assertEqual(self.write(FAKE_SSN[:3] + "​" + FAKE_SSN[3:])[0], "deny")

    def test_soft_hyphen_and_word_joiner(self):
        self.assertEqual(self.write(FAKE_SSN[:2] + "­" + FAKE_SSN[2:5] + "⁠" + FAKE_SSN[5:])[0], "deny")

    def test_en_dash_ssn(self):
        self.assertEqual(self.write(FAKE_SSN.replace("-", "–"))[0], "deny")

    def test_fullwidth_digits(self):
        fw = "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in FAKE_SSN)
        self.assertEqual(self.write(fw)[0], "deny")

    def test_arabic_indic_digits(self):
        ar = "".join(chr(0x0660 + int(c)) if c.isdigit() else c for c in FAKE_SSN)
        self.assertEqual(self.write(ar)[0], "deny")

    def test_prompt_with_zero_width_ssn_blocked(self):
        r = run(["hook", "userprompt"], stdin=json.dumps({"cwd": self.repo.dir, "prompt": "look up " + FAKE_SSN.replace("-", "-​")}),
                cwd=self.repo.dir, env={"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev})
        self.assertEqual(json.loads(r.stdout)["decision"], "block")
        assert_no_leak(self, r.stdout, r.stderr)


class NewPatternTests(Base):
    def test_labeled_ssn_without_dashes(self):
        d, why = self.hook("Write", {"file_path": "src/a.py", "content": "ssn = '%s'\n" % FAKE_SSN_DIGITS})
        self.assertEqual(d, "deny")
        self.assertIn("PHI-SSN-LABELED", why)

    def test_hl7_segment_denied_in_source(self):
        msg = "PID|1||" + FAKE_MRN_VALUE + "^^^HOSP||DOE^JANE"
        d, why = self.hook("Write", {"file_path": "src/hl7.ts", "content": "const m = `%s`;\n" % msg})
        self.assertEqual(d, "deny")
        self.assertIn("PHI-HL7", why)

    def test_hl7_segment_allowed_in_synthetic_fixture(self):
        msg = "PID|1||TEST-0001^^^HOSP||TESTPATIENT^ALPHA"
        d, _ = self.hook("Write", {"file_path": "tests/fixtures/hl7.ts",
                                   "content": "// synthetic-data\nexport const m = `%s`;\n" % msg})
        self.assertIsNone(d)

    def test_fhir_patient_unmarked_fixture_asks(self):
        body = json.dumps({"resourceType": "Patient", "birthDate": "1980-02-03", "name": [{"family": "X"}]})
        d, why = self.hook("Write", {"file_path": "tests/fixtures/patient.json", "content": body})
        self.assertEqual(d, "ask")
        self.assertIn("PHI-FHIR-PATIENT", why)

    def test_member_id_literal_asks(self):
        d, why = self.hook("Write", {"file_path": "src/claim.ts", "content": "const memberId = 'W' + 0; const x = { member_id: 'ZQX99881234' };\n"})
        self.assertEqual(d, "ask")
        self.assertIn("PHI-MEMBER-ID", why)

    def test_member_id_synthetic_prefix_passes(self):
        d, _ = self.hook("Write", {"file_path": "src/claim.ts", "content": "const x = { member_id: 'TEST-99881234' };\n"})
        self.assertIsNone(d)

    def test_multiline_log_call(self):
        d, why = self.hook("Write", {"file_path": "src/api/r.ts", "content": "logger.info(\n  'loaded',\n  patient\n);\n"})
        self.assertEqual(d, "deny")
        self.assertIn("LOG-PHI", why)

    def test_multiline_log_of_ids_passes(self):
        d, _ = self.hook("Write", {"file_path": "src/api/r.ts", "content": "logger.info(\n  'loaded',\n  patient.id\n);\n"})
        self.assertIsNone(d)


class DataFileTests(Base):
    policy = {"mode": "warn"}

    def test_clinical_file_denied_even_in_warn_mode(self):
        d, why = self.hook("Write", {"file_path": "samples/adt.hl7", "content": "x\n"})
        self.assertEqual(d, "deny")
        self.assertIn("DATAFILE-CLINICAL", why)

    def test_database_file_denied(self):
        d, _ = self.hook("Write", {"file_path": "local.sqlite", "content": "x"})
        self.assertEqual(d, "deny")

    def test_csv_roster_flagged(self):
        d, why = self.hook("Write", {"file_path": "data/people.csv", "content": "first_name,last_name,dob\nA,B,2000-01-01\n"})
        self.assertIn("DATAFILE-TABULAR", why)
        self.assertIn("PHI-CSV-ROSTER", why)

    def test_redirect_creates_data_file(self):
        d, why = self.bash("psql -c 'select 1' > dump.sql.gz")
        self.assertEqual(d, "deny")
        self.assertIn("DATAFILE-DUMP", why)


class GuardTamperTests(Base):
    policy = {"mode": "warn"}

    def test_edit_policy_asks_even_in_warn_mode(self):
        d, why = self.hook("Edit", {"file_path": ".hipaa-guardrails.json", "old_string": "warn", "new_string": "warn"})
        self.assertEqual(d, "ask")
        self.assertIn("GUARD-CONFIG", why)

    def test_write_claude_settings_asks(self):
        for p in (".claude/settings.json", ".claude/settings.local.json", ".github/workflows/x.yml", ".githooks/pre-commit", "CODEOWNERS"):
            d, why = self.hook("Write", {"file_path": p, "content": "{}\n"})
            self.assertEqual(d, "ask", p)

    def test_hooks_path_change(self):
        self.assertEqual(self.bash("git config core.hooksPath /dev/null")[0], "ask")
        self.assertEqual(self.bash("git -c core.hooksPath=/tmp/none commit -m x")[0], "ask")

    def test_plugin_disable(self):
        self.assertEqual(self.bash("claude plugin disable hipaa-guardrails@hipaa-guardrails")[0], "ask")

    def test_remove_or_move_policy(self):
        self.assertEqual(self.bash("rm .hipaa-guardrails.json")[0], "ask")
        self.assertEqual(self.bash("git mv .hipaa-guardrails.json old.json")[0], "ask")

    def test_skip_env_vars_denied(self):
        self.assertEqual(self.bash("HUSKY=0 git commit -m x")[0], "deny")

    def test_no_verify_short_flag(self):
        self.assertEqual(self.bash("git commit -n -m x")[0], "deny")
        self.assertEqual(self.bash("git commit --no-verify -m x")[0], "deny")

    def test_redirect_into_settings(self):
        d, why = self.bash("echo '{\"disableAllHooks\": true}' > .claude/settings.local.json")
        self.assertEqual(d, "ask")

    def test_sed_in_place_on_workflow(self):
        self.assertEqual(self.bash("sed -i 's/a/b/' .github/workflows/ci.yml")[0], "ask")

    def test_tee_into_git_hook(self):
        self.assertEqual(self.bash("echo exit 0 | tee .githooks/pre-commit")[0], "ask")

    def test_python_writes_policy(self):
        self.assertEqual(self.bash("python3 -c \"open('.hipaa-guardrails.json','w').write('{}')\"")[0], "ask")

    def test_disable_all_hooks_written_by_cli(self):
        self.assertEqual(self.bash("claude --settings '{\"disableAllHooks\": true}' -p hi")[0], "ask")


class ShellReadTests(Base):
    def setUp(self):
        super().setUp()
        self.repo.write("exports/run.csv", "id\n1\n")
        self.repo.write("data/people.csv", "first_name,last_name,ssn\nA,B,%s\n" % FAKE_SSN)
        self.repo.write("data/synth.csv", "# synthetic-data\nfirst_name,last_name,ssn\nA,B,%s\n" % SYNTH_SSN)
        self.repo.write(".env", "TOKEN=x\n")

    def test_cd_then_glob(self):
        self.assertEqual(self.bash("cd exports && cat *")[0], "deny")

    def test_list_phi_dir(self):
        self.assertEqual(self.bash("ls exports")[0], "deny")

    def test_python_one_liner_reads_phi_path(self):
        self.assertEqual(self.bash("python3 -c \"print(open('exports/run.csv').read())\"")[0], "deny")

    def test_content_sniff_on_cat(self):
        d, why = self.bash("head -5 data/people.csv")
        self.assertEqual(d, "deny")
        self.assertIn("PHI-READ-CONTENT", why)
        assert_no_leak(self, why)

    def test_content_sniff_on_read_tool(self):
        d, why = self.hook("Read", {"file_path": os.path.join(self.repo.dir, "data/people.csv")})
        self.assertEqual(d, "deny")
        self.assertIn("PHI-READ-CONTENT", why)

    def test_synthetic_file_reads_fine(self):
        self.assertIsNone(self.bash("cat data/synth.csv")[0])
        self.assertIsNone(self.hook("Read", {"file_path": os.path.join(self.repo.dir, "data/synth.csv")})[0])

    def test_env_read_asks(self):
        self.assertEqual(self.hook("Read", {"file_path": os.path.join(self.repo.dir, ".env")})[0], "ask")
        self.assertEqual(self.bash("cat .env")[0], "ask")

    def test_script_indirection(self):
        self.repo.write("run.sh", "#!/bin/sh\ncat exports/run.csv\n")
        d, why = self.bash("bash run.sh")
        self.assertEqual(d, "deny")
        self.assertIn("run.sh", why)

    def test_heredoc_source_file_checked(self):
        d, why = self.bash("cat > src/log.ts <<'EOF'\nconsole.log(patient)\nEOF")
        self.assertEqual(d, "deny")
        self.assertIn("LOG-PHI", why)

    def test_glob_tool_into_phi_dir(self):
        self.assertEqual(self.hook("Glob", {"pattern": "exports/**/*.csv"})[0], "deny")

    def test_marker_in_command_never_waives(self):
        pol = {"exceptions": [exc("EXC-1", ["PHI-SSN"], ["**/*"])]}
        self.repo.write(".hipaa-guardrails.json", json.dumps(pol))
        self.assertEqual(self.bash("echo %s # phi-ok: EXC-1" % FAKE_SSN)[0], "deny")


class EgressTests(Base):
    policy = {"phi_mcp_tools": ["^mcp__EHR__get_patient$"], "runtime": {"bedrock_is_baa_covered": True}}

    def test_webfetch_with_ssn(self):
        d, why = self.hook("WebFetch", {"url": "https://example.com/?q=" + FAKE_SSN, "prompt": "x"})
        self.assertEqual(d, "deny")
        self.assertIn("PHI-EGRESS", why)
        assert_no_leak(self, why)

    def test_websearch_with_labeled_mrn(self):
        self.assertEqual(self.hook("WebSearch", {"query": "mrn: %s results" % FAKE_MRN_VALUE})[0], "deny")

    def test_websearch_plain_is_fine(self):
        self.assertIsNone(self.hook("WebSearch", {"query": "next.js middleware docs"})[0])

    def test_agent_prompt_with_ssn(self):
        self.assertEqual(self.hook("Agent", {"prompt": "fix record " + FAKE_SSN, "description": "x"})[0], "deny")
        self.assertEqual(self.hook("Task", {"prompt": "fix record " + FAKE_SSN, "description": "x"})[0], "deny")

    def test_agent_prompt_ok_on_covered_runtime(self):
        self.assertIsNone(self.hook("Agent", {"prompt": "fix record " + FAKE_SSN}, env={"CLAUDE_CODE_USE_BEDROCK": "1"})[0])

    def test_webfetch_denied_even_on_covered_runtime(self):
        self.assertEqual(self.hook("WebFetch", {"url": "https://example.com/" + FAKE_SSN}, env={"CLAUDE_CODE_USE_BEDROCK": "1"})[0], "deny")

    def test_mcp_other_tool_with_ssn_arg(self):
        d, why = self.hook("mcp__notes__create", {"body": {"text": "patient " + FAKE_SSN}})
        self.assertEqual(d, "deny")
        self.assertIn("PHI-EGRESS", why)

    def test_mcp_phi_tool_on_covered_runtime(self):
        self.assertIsNone(self.hook("mcp__EHR__get_patient", {"ssn": FAKE_SSN}, env={"CLAUDE_CODE_USE_BEDROCK": "1"})[0])

    def test_mcp_path_arg(self):
        self.assertEqual(self.hook("mcp__fs__read_file", {"path": "exports/a.csv"})[0], "deny")

    def test_secret_in_webfetch(self):
        d, why = self.hook("WebFetch", {"url": "https://example.com/?k=" + "sk-ant-" + "a" * 40})
        self.assertEqual(d, "deny")
        self.assertIn("SECRET-EGRESS", why)


class ExceptionTests(Base):
    def set_policy(self, **pol):
        self.repo.write(".hipaa-guardrails.json", json.dumps(pol))

    def test_expired_exception_does_not_waive(self):
        self.set_policy(exceptions=[exc("EXC-9", ["LOG-PHI"], ["src/**"], approved_on="2025-01-01", expires="2025-06-01")])
        d, why = self.hook("Write", {"file_path": "src/r.ts", "content": "console.log(patient); // phi-ok: EXC-9\n"})
        self.assertEqual(d, "deny")
        self.assertIn("EXCEPTION-EXPIRED", why)

    def test_exception_for_other_rule(self):
        self.set_policy(exceptions=[exc("EXC-3", ["TLS-PLAIN-HTTP"], ["src/**"])])
        d, why = self.hook("Write", {"file_path": "src/r.ts", "content": "console.log(patient); // phi-ok: EXC-3\n"})
        self.assertEqual(d, "deny")
        self.assertIn("WAIVER-UNREGISTERED", why)

    def test_exception_for_other_path(self):
        self.set_policy(exceptions=[exc("EXC-4", ["LOG-PHI"], ["src/admin/**"])])
        self.assertEqual(self.hook("Write", {"file_path": "src/r.ts", "content": "console.log(patient); // phi-ok: EXC-4\n"})[0], "deny")

    def test_path_scope_exception(self):
        self.set_policy(exceptions=[exc("EXC-5", ["DATAFILE-TABULAR"], ["reference/icd10/*.csv"], scope="path")])
        self.assertIsNone(self.hook("Write", {"file_path": "reference/icd10/codes.csv", "content": "code,label\nA00,Cholera\n"})[0])
        self.assertEqual(self.hook("Write", {"file_path": "reference/other.csv", "content": "code\n"})[0], "ask")

    def test_never_excepted_rule_rejected(self):
        self.set_policy(phi_mcp_tools=["^mcp__X__get$"], exceptions=[exc("EXC-6", ["MCP-PHI-TOOL"], ["**/*"], scope="path")])
        self.assertEqual(self.hook("mcp__X__get", {})[0], "deny")
        r = run(["validate-config"], cwd=self.repo.dir)
        self.assertEqual(r.returncode, 1)
        self.assertIn("can't be excepted", r.stdout)

    def test_exception_missing_approver_is_invalid(self):
        e = exc("EXC-7", ["LOG-PHI"], ["src/**"])
        del e["approver"]
        self.set_policy(exceptions=[e])
        self.assertEqual(self.hook("Write", {"file_path": "src/r.ts", "content": "console.log(patient); // phi-ok: EXC-7\n"})[0], "deny")
        r = run(["validate-config"], cwd=self.repo.dir)
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing approver", r.stdout)

    def test_exception_longer_than_a_year_invalid(self):
        self.set_policy(exceptions=[exc("EXC-8", ["LOG-PHI"], ["src/**"], expires=(date.today() + timedelta(days=400)).isoformat())])
        self.assertEqual(run(["validate-config"], cwd=self.repo.dir).returncode, 1)


class ConfigTests(Base):
    def test_broken_json_falls_back_to_strict_default(self):
        self.repo.write(".hipaa-guardrails.json", '{"mode": "warn", ')
        d, why = self.hook("Write", {"file_path": "src/r.ts", "content": "console.log(patient);\n"})
        self.assertEqual(d, "deny")  # default policy is enforce mode
        self.assertIn("not valid JSON", why)
        self.assertEqual(run(["validate-config"], cwd=self.repo.dir).returncode, 1)

    def test_bad_regex_reported_not_crashing(self):
        self.repo.write(".hipaa-guardrails.json", json.dumps({"custom_rules+": [{"id": "X-BAD", "regex": "(unclosed", "action": "deny"}]}))
        d, _ = self.hook("Write", {"file_path": "src/r.ts", "content": "export const a = 1;\n"})
        self.assertIn(d, (None, "message"))
        r = run(["validate-config"], cwd=self.repo.dir)
        self.assertEqual(r.returncode, 1)
        self.assertIn("bad regex", r.stdout)

    def test_requires_newer_plugin(self):
        self.repo.write(".hipaa-guardrails.json", json.dumps({"requires_plugin": ">=9.0.0"}))
        self.assertEqual(run(["validate-config"], cwd=self.repo.dir).returncode, 1)

    def test_non_executable_git_hook_flagged(self):
        self.repo.write(".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
        self.repo.git("add", "-A")
        self.repo.git("update-index", "--chmod=-x", ".githooks/pre-commit")
        r = run(["validate-config"], cwd=self.repo.dir)
        self.assertIn("GUARD-HOOK-NOT-EXECUTABLE", r.stdout)
        self.repo.git("update-index", "--chmod=+x", ".githooks/pre-commit")
        self.assertNotIn("GUARD-HOOK-NOT-EXECUTABLE", run(["validate-config"], cwd=self.repo.dir).stdout)

    def test_unknown_key_warns(self):
        self.repo.write(".hipaa-guardrails.json", json.dumps({"policy_version": "1.0.0", "modee": "warn"}))
        r = run(["validate-config"], cwd=self.repo.dir)
        self.assertEqual(r.returncode, 0)
        self.assertIn("CONFIG-UNKNOWN-KEY", r.stdout)

    def test_fail_closed(self):
        payload = json.dumps({"cwd": self.repo.dir, "tool_name": "Write", "tool_input": ["not", "a", "dict"]})
        r = run(["hook", "pretooluse"], stdin=payload, cwd=self.repo.dir, env={"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev})
        self.assertEqual(r.returncode, 1)  # fail open by default: non-blocking error
        self.repo.write(".hipaa-guardrails.json", json.dumps({"fail_closed": True}))
        r = run(["hook", "pretooluse"], stdin=payload, cwd=self.repo.dir, env={"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev})
        self.assertEqual(r.returncode, 2)  # exit 2 blocks the tool call


class EvidenceTests(Base):
    def g(self, *args):
        return run(list(args), cwd=self.repo.dir, env={"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev})

    def test_records_written_and_chain_verifies(self):
        self.hook("Write", {"file_path": "src/a.ts", "content": "export const a = 1;\n"})
        self.hook("Write", {"file_path": "src/b.ts", "content": "const s = '%s';\n" % FAKE_SSN})
        self.bash("cat README.md")
        r = self.g("evidence", "verify")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("3 record(s), chain intact", r.stdout)
        recs = [json.loads(l) for l in self.evidence_text().splitlines()]
        self.assertEqual([x["decision"] for x in recs], ["allow", "deny", "allow"])
        self.assertEqual(recs[1]["findings"][0]["rule"], "PHI-SSN")
        self.assertEqual(recs[1]["prev"], recs[0]["hash"])
        for key in ("ts", "policy", "plugin_version", "repo", "actor", "mode", "tool"):
            self.assertIn(key, recs[1])
        assert_no_leak(self, self.evidence_text())

    def test_tampering_detected(self):
        for i in range(3):
            self.hook("Write", {"file_path": "src/%d.ts" % i, "content": "console.log(patient);\n"})
        path = glob.glob(os.path.join(self.ev, "*.jsonl"))[0]
        lines = open(path).read().splitlines()
        edited = lines[:]
        edited[1] = edited[1].replace('"deny"', '"allow"', 1)
        open(path, "w").write("\n".join(edited) + "\n")
        self.assertEqual(self.g("evidence", "verify").returncode, 1)
        open(path, "w").write("\n".join([lines[0], lines[2]]) + "\n")
        r = self.g("evidence", "verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("removed or reordered", r.stdout)

    def test_chain_links_across_months(self):
        self.hook("Write", {"file_path": "src/a.ts", "content": "export const a = 1;\n"})
        cur = glob.glob(os.path.join(self.ev, "*.jsonl"))[0]
        os.rename(cur, os.path.join(self.ev, "2000-01.jsonl"))
        self.hook("Write", {"file_path": "src/b.ts", "content": "export const b = 1;\n"})
        self.assertEqual(self.g("evidence", "verify").returncode, 0)
        os.remove(os.path.join(self.ev, "2000-01.jsonl"))
        self.assertEqual(self.g("evidence", "verify").returncode, 1)

    def test_phi_paths_hashed(self):
        self.hook("Read", {"file_path": os.path.join(self.repo.dir, "exports/jane-doe.csv")})
        text = self.evidence_text()
        self.assertIn("PHI-READ", text)
        self.assertNotIn("jane-doe", text)

    def test_export_bundle(self):
        self.hook("Write", {"file_path": "src/b.ts", "content": "console.log(patient);\n"})
        out = os.path.join(self.repo.dir, "bundle")
        r = self.g("evidence", "export", "--out", out)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for name in ("report.md", "report.json", "policy-merged.json", "MANIFEST.sha256"):
            self.assertTrue(os.path.exists(os.path.join(out, name)), name)
        r = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"], cwd=out, stdout=subprocess.PIPE, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("LOG-PHI", open(os.path.join(out, "report.md")).read())

    def test_log_allowed_off(self):
        self.repo.write(".hipaa-guardrails.json", json.dumps({"evidence": {"log_allowed": False}}))
        self.hook("Write", {"file_path": "src/a.ts", "content": "export const a = 1;\n"})
        self.assertEqual(self.evidence_text(), "")

    def test_no_value_leaks_anywhere(self):
        attempts = [
            ("Write", {"file_path": "src/a.ts", "content": "const s = '%s';\n" % FAKE_SSN}),
            ("Write", {"file_path": "tests/f.ts", "content": "mrn: '%s'\n" % FAKE_MRN_VALUE}),
            ("Bash", {"command": "echo ssn=%s" % FAKE_SSN_DIGITS}),
            ("WebSearch", {"query": FAKE_SSN}),
            ("mcp__x__y", {"q": FAKE_SSN}),
        ]
        outs = []
        for tool, tin in attempts:
            payload = json.dumps({"cwd": self.repo.dir, "tool_name": tool, "tool_input": tin, "session_id": "s1"})
            r = run(["hook", "pretooluse"], stdin=payload, cwd=self.repo.dir, env={"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev})
            outs += [r.stdout, r.stderr]
        r = run(["hook", "userprompt"], stdin=json.dumps({"cwd": self.repo.dir, "prompt": "ssn " + FAKE_SSN}), cwd=self.repo.dir,
                env={"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev})
        outs += [r.stdout, r.stderr, self.evidence_text(), self.g("evidence", "report").stdout,
                 self.g("evidence", "report", "--format", "json").stdout]
        assert_no_leak(self, *outs)


class PolicyChangeCITests(Base):
    policy = {"policy_version": "1.0.0", "mode": "enforce",
              "change_log": [{"version": "1.0.0", "date": "2026-11-01", "approver": OWNER, "summary": "initial"}]}

    def branch_with_policy(self, pol):
        self.repo.git("checkout", "-q", "-b", "feature")
        self.repo.write(".hipaa-guardrails.json", json.dumps(pol))
        self.repo.git("add", "-A")
        self.repo.git("commit", "-q", "-m", "policy")

    def scan(self, extra_env=None):
        e = {"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev}
        e.update(extra_env or {})
        return run(["scan", "--diff", "main", "--github"], cwd=self.repo.dir, env=e)

    def test_unrecorded_change_fails(self):
        pol = dict(self.policy, mode="warn")
        self.branch_with_policy(pol)
        r = self.scan()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("POLICY-CHANGE-UNRECORDED", r.stdout)
        self.assertIn("mode changed from enforce to warn", r.stdout)

    def test_recorded_change_passes_and_lists_loosening(self):
        pol = dict(self.policy, mode="warn", policy_version="1.1.0",
                   vendors={"supabase": {"status": "baa"}},
                   change_log=self.policy["change_log"] + [{"version": "1.1.0", "date": "2026-11-02", "approver": OWNER, "summary": "BAA signed"}])
        self.branch_with_policy(pol)
        summary = os.path.join(self.repo.dir, "summary.md")
        r = self.scan({"GITHUB_STEP_SUMMARY": summary})
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("POLICY-LOOSENED", r.stdout)
        self.assertIn("vendor supabase: unverified -> baa", r.stdout)
        self.assertIn("1.0.0 -> 1.1.0", open(summary).read())
        rec = json.loads(self.evidence_text().splitlines()[-1])
        self.assertEqual(rec["event"], "ci")
        self.assertEqual(rec["policy_change"]["approver"], OWNER)

    def test_binary_data_files_in_pr(self):
        self.repo.git("checkout", "-q", "-b", "feature")
        with open(os.path.join(self.repo.dir, "local.sqlite"), "wb") as f:
            f.write(b"\x00\x01binary")
        self.repo.git("add", "-A")
        self.repo.git("commit", "-q", "-m", "db")
        r = self.scan()
        self.assertEqual(r.returncode, 1)
        self.assertIn("DATAFILE-DUMP", r.stdout)


class LoosenedPolicyTests(Base):
    policy = PolicyChangeCITests.policy
    scan = PolicyChangeCITests.scan

    def test_code_checked_against_base_policy_when_loosened(self):
        self.repo.git("checkout", "-q", "-b", "feature")
        pol = dict(self.policy, policy_version="1.1.0",
                   log_rule={"action": "warn"},
                   change_log=self.policy["change_log"] + [{"version": "1.1.0", "date": "2026-11-02", "approver": OWNER, "summary": "soften logging"}])
        self.repo.write(".hipaa-guardrails.json", json.dumps(pol))
        self.repo.write("src/r.ts", "console.log(patient);\n")
        self.repo.git("add", "-A")
        self.repo.git("commit", "-q", "-m", "loosen and use")
        r = self.scan()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("POLICY-BASE-USED", r.stdout)
        self.assertIn("rule LOG-PHI: deny -> warn", r.stdout)


class PreCommitInstallTests(unittest.TestCase):
    """The template's git pre-commit hook finds the checker in a plugin install laid out the way Claude Code lays it out."""
    def test_precommit_finds_installed_plugin(self):
        cfg = tempfile.mkdtemp(prefix="hg-cfg-")
        plugin_src = os.path.dirname(os.path.dirname(GUARD))
        for ver in ("0.1.0", "0.2.0"):
            dst = os.path.join(cfg, "plugins", "cache", "hipaa-guardrails", "hipaa-guardrails", ver)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            subprocess.run(["cp", "-r", plugin_src, dst], check=True)
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(GUARD))))
        hook = os.path.join(root, "template-repo", ".githooks", "pre-commit")
        self.assertTrue(os.path.exists(hook), "template-repo/.githooks/pre-commit is missing")
        repo = Repo({})
        try:
            repo.write("src/a.ts", "const s = '%s';\n" % FAKE_SSN)
            repo.git("add", "-A")
            env = dict(os.environ, CLAUDE_CONFIG_DIR=cfg, HIPAA_GUARDRAILS_EVIDENCE_DIR=tempfile.mkdtemp())
            r = subprocess.run(["sh", hook], cwd=repo.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("PHI-SSN", r.stdout)
            assert_no_leak(self, r.stdout, r.stderr)
            env["CLAUDE_CONFIG_DIR"] = tempfile.mkdtemp()
            r = subprocess.run(["sh", hook], cwd=repo.dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertIn("checker not found", r.stderr)
        finally:
            repo.close()


class FullScanTests(Base):
    def test_baseline(self):
        self.repo.write("src/old.ts", "console.log(patient);\n")
        self.repo.git("add", "-A")
        self.repo.git("commit", "-q", "-m", "old")
        base = os.path.join(self.repo.dir, ".hipaa-guardrails.baseline.json")
        env = {"HIPAA_GUARDRAILS_EVIDENCE_DIR": self.ev}
        self.assertEqual(run(["scan", "--all"], cwd=self.repo.dir, env=env).returncode, 1)
        run(["scan", "--all", "--write-baseline", base], cwd=self.repo.dir, env=env)
        self.assertEqual(run(["scan", "--all", "--baseline", base], cwd=self.repo.dir, env=env).returncode, 0)
        self.repo.write("src/new.ts", "console.log(rows);\n")
        self.repo.git("add", "-A")
        r = run(["scan", "--all", "--baseline", base], cwd=self.repo.dir, env=env)
        self.assertEqual(r.returncode, 1)
        self.assertIn("src/new.ts", r.stdout)
        self.assertNotIn("src/old.ts", r.stdout)


class PerformanceTests(Base):
    def test_large_write_under_budget(self):
        body = "".join("export const v%d = compute(%d); // ordinary line\n" % (i, i) for i in range(5000))
        t = time.time()
        d, _ = self.hook("Write", {"file_path": "src/big.ts", "content": body})
        self.assertIsNone(d)
        self.assertLess(time.time() - t, 5.0)


if __name__ == "__main__":
    unittest.main()
