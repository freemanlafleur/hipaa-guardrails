#!/usr/bin/env python3
"""HIPAA guardrails: one checker for Claude Code hooks, git hooks and CI.

Usage:
  guard.py hook pretooluse            Claude Code PreToolUse hook (JSON on stdin)
  guard.py hook userprompt            Claude Code UserPromptSubmit hook (JSON on stdin)
  guard.py staged [--all]             Check what `git commit` would record (pre-commit hook)
  guard.py scan --diff BASE           Check what a branch adds since BASE (CI)
  guard.py scan --files F... | --all  Check whole files (scheduled full scan)
        [--baseline FILE] [--write-baseline FILE]
  guard.py validate-config            Check .hipaa-guardrails.json (schema, regexes, exceptions)
  guard.py explain                    Print the merged policy for this repo
  guard.py evidence path|head|verify|report|export   Work with the evidence log
        report [--since YYYY-MM-DD] [--format md|json]
        export --out DIR [--since YYYY-MM-DD]
  guard.py version

Policy: the plugin default (../policy/default-policy.json) merged with the repo's
.hipaa-guardrails.json. Standard library only, Python 3.8+.

Nothing this checker prints or records ever contains a matched value: findings
carry the rule, file and line only, and evidence records never hold file
contents, prompts or commands.
"""
import datetime
import fnmatch
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import unicodedata

PLUGIN_VERSION = "0.2.0"
SCHEMA_VERSION = 2
HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.abspath(os.path.join(HERE, ".."))
DEFAULT_POLICY = os.path.join(PLUGIN_ROOT, "policy", "default-policy.json")
REPO_POLICY_NAME = ".hipaa-guardrails.json"
SEVERITY = {"deny": 3, "ask": 2, "warn": 1, "allow": 0}
MARKER_DEFAULT = "phi" + "-ok:"   # built at runtime so this file doesn't contain the marker itself
GENESIS = "0" * 64
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

KNOWN_KEYS = {
    "schema_version", "policy_version", "default_policy_version", "requires_plugin", "change_log", "owner",
    "mode", "always_enforce", "never_excepted", "fail_closed", "inline_allow_marker",
    "unregistered_waiver_action", "exception_expiry_warning_days", "synthetic_marker", "runtime", "ci",
    "evidence", "protected_paths", "sniff", "ignore_paths", "strict_paths", "source_extensions",
    "phi_read_paths", "phi_mcp_tools", "phi_patterns", "file_level_rules", "synthetic_email_domains",
    "strict_contact_rules", "fixture_marker_rule", "log_rule", "secret_patterns", "env_file_regex",
    "env_file_allowed_regex", "data_file_rules", "unverified_action", "vendor_check_extensions",
    "vendor_check_files", "vendor_exempt_paths", "vendors", "custom_rules", "blocked_commands", "exceptions",
}


# ================================================================ text normalization

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎͏"), None)
_DASHES = dict.fromkeys(map(ord, "‐‑‒–—―−﹘﹣－"), "-")


def normalize(text):
    """Fold the tricks that make an identifier slip past a regex: zero-width characters,
    look-alike dashes, full-width and other-script digits, compatibility forms."""
    if not text or text.isascii():
        return text or ""
    t = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).translate(_DASHES)
    if not t.isascii():
        t = "".join(str(unicodedata.digit(c)) if (not c.isascii() and c.isdigit() and unicodedata.digit(c, None) is not None) else c for c in t)
    return t


# ================================================================ policy

def deep_merge(base, over):
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            if k.startswith("_"):
                continue
            if k.endswith("+") and isinstance(v, list):  # "key+": append to the default list
                key = k[:-1]
                out[key] = list(out.get(key, []) or []) + v
            else:
                out[k] = deep_merge(base.get(k), v) if k in base else v
        return out
    return over


def find_repo_root(start):
    cur = os.path.abspath(start or os.getcwd())
    while True:
        if os.path.exists(os.path.join(cur, REPO_POLICY_NAME)) or os.path.exists(os.path.join(cur, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return os.path.abspath(start or os.getcwd())
        cur = parent


def file_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def load_default():
    with open(DEFAULT_POLICY) as f:
        return json.load(f)


def load_policy(root, repo_text=None):
    """Return the merged policy. A repo config that can't be parsed falls back to the
    plugin default (enforce mode, no exceptions), which is stricter, and is reported."""
    policy = load_default()
    problems = []
    repo_file = os.path.join(root, REPO_POLICY_NAME)
    raw = None
    if repo_text is None and os.path.exists(repo_file):
        try:
            with open(repo_file) as f:
                repo_text = f.read()
        except Exception as e:
            problems.append("couldn't read %s (%s)" % (REPO_POLICY_NAME, e.__class__.__name__))
    if repo_text is not None:
        try:
            raw = json.loads(repo_text)
            if not isinstance(raw, dict):
                raise ValueError("top level is not an object")
            policy = deep_merge(policy, raw)
        except Exception as e:
            problems.append("%s is not valid JSON (%s); using the plugin default policy" % (REPO_POLICY_NAME, str(e)[:80]))
            raw = None
    policy["_repo_raw"] = raw
    policy["_repo_policy_found"] = raw is not None
    policy["_load_problems"] = problems
    policy["_policy_sha256"] = hashlib.sha256((repo_text or "").encode()).hexdigest() if repo_text is not None else None
    policy["_default_sha256"] = file_sha256(DEFAULT_POLICY)
    return policy


def policy_version(policy):
    raw = policy.get("_repo_raw") or {}
    return raw.get("policy_version") or "default-" + str(policy.get("default_policy_version", PLUGIN_VERSION))


def covered_runtime(policy):
    rt = policy.get("runtime", {}) or {}
    on_bedrock = os.environ.get("CLAUDE_CODE_USE_BEDROCK", "").lower() in ("1", "true", "yes")
    return bool(rt.get("bedrock_is_baa_covered")) and on_bedrock


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3]) or (0,)


def today():
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_date(s):
    try:
        return datetime.date.fromisoformat(str(s))
    except Exception:
        return None


# ================================================================ helpers

def rel(path, root):
    try:
        p = os.path.relpath(os.path.abspath(path), root)
    except ValueError:
        return path.replace(os.sep, "/")
    return p.replace(os.sep, "/")


def glob_match(path, patterns):
    if not path:
        return False
    while path.startswith("./"):
        path = path[2:]
    for pat in patterns or []:
        if fnmatch.fnmatchcase(path, pat):
            return True
        if pat.startswith("**/") and fnmatch.fnmatchcase(path, pat[3:]):
            return True
        if "/" not in pat and fnmatch.fnmatchcase(os.path.basename(path), pat):
            return True
    return False


def dir_match(path, patterns):
    """True when a directory path, or anything inside it, matches a pattern."""
    path = path.rstrip("/")
    return glob_match(path, patterns) or glob_match(path + "/_", patterns)


def prefix_match(rule, prefixes):
    return any(rule == p or rule.startswith(p) for p in prefixes or [])


class Finding:
    def __init__(self, rule, action, message, path=None, line=None, mark=None):
        self.rule, self.action, self.message, self.path, self.line = rule, action, message, path, line
        self.mark = mark          # inline waiver id on the line (None = no marker, "" = marker without id)
        self.exception = None     # id of the registered exception that covers this finding

    def where(self):
        if self.path and self.line:
            return "%s:%s" % (self.path, self.line)
        return self.path or "(command)"

    def text(self):
        return "[%s] %s: %s" % (self.rule, self.where(), self.message)


def strip_string_literals(line):
    """Drop the contents of quoted strings, keep ${...} in template literals and {..} in f-strings."""
    out, i, n = [], 0, len(line)
    while i < n:
        c = line[i]
        if c in "'\"":
            j = i + 1
            while j < n and line[j] != c:
                j += 2 if line[j] == "\\" else 1
            prefix = line[max(0, i - 2):i].lower()
            if prefix.endswith("f") and (len(prefix) < 2 or not prefix[0].isalnum() or prefix[0] in "rb"):
                out.append(" " + " ".join(re.findall(r"\{([^{}]*)\}", line[i + 1:j])) + " ")
            else:
                out.append(c + c)
            i = j + 1
        elif c == "`":
            j = i + 1
            while j < n and line[j] != "`":
                if line[j] == "\\":
                    j += 2
                    continue
                if line.startswith("${", j):
                    depth, k = 1, j + 2
                    while k < n and depth:
                        depth += {"{": 1, "}": -1}.get(line[k], 0)
                        k += 1
                    out.append(" " + line[j + 2:k - 1] + " ")
                    j = k
                    continue
                j += 1
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def safe_compile(rx, problems, where):
    try:
        return re.compile(rx)
    except Exception as e:
        problems.append("%s: bad regex (%s)" % (where, str(e)[:60]))
        return None


# ================================================================ content checks

class Checker:
    def __init__(self, policy, root):
        self.p = policy
        self.root = root
        self.problems = list(policy.get("_load_problems", []))
        self.marker = policy.get("inline_allow_marker", MARKER_DEFAULT)
        self.marker_re = re.compile(re.escape(self.marker) + r"\s*(" + ID_RE.pattern + r")?")
        self.synthetic_marker = policy.get("synthetic_marker", "synthetic-data")
        self.phi = self._rules("phi_patterns")
        self.secrets = self._rules("secret_patterns")
        self.custom = self._rules("custom_rules")
        lr = policy.get("log_rule", {}) or {}
        self.log_call = safe_compile(lr["call_regex"], self.problems, "log_rule.call_regex") if lr.get("call_regex") else None
        self.log_risky = safe_compile(lr["risky_regex"], self.problems, "log_rule.risky_regex") if lr.get("risky_regex") else None
        self.log_bare = safe_compile(lr["bare_object_regex"], self.problems, "log_rule.bare_object_regex") if lr.get("bare_object_regex") else None
        self.log_safe = safe_compile(lr["safe_expr_regex"], self.problems, "log_rule.safe_expr_regex") if lr.get("safe_expr_regex") else None
        self.env_re = safe_compile(policy.get("env_file_regex", r"(^|/)\.env$"), self.problems, "env_file_regex") or re.compile(r"(^|/)\.env$")
        self.env_ok_re = safe_compile(policy.get("env_file_allowed_regex", r"\.example$"), self.problems, "env_file_allowed_regex") or re.compile(r"\.example$")
        self.email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
        self.phone_re = re.compile(r"(?<![\d.])(?:\+?1[ .-]?)?\(?([2-9]\d{2})\)?[ .-]?(\d{3})[ .-](\d{4})(?![\d.])")
        fm = policy.get("fixture_marker_rule", {}) or {}
        self.fixture_field = safe_compile(fm["field_regex"], self.problems, "fixture_marker_rule") if fm.get("field_regex") else None
        self.file_rules = []
        for r in policy.get("file_level_rules", []) or []:
            pats = [safe_compile(x, self.problems, r.get("id", "file_level_rules")) for x in r.get("all_of", [])]
            hdr = [safe_compile(x, self.problems, r.get("id", "file_level_rules")) for x in r.get("header_all_of", [])]
            if None not in pats and None not in hdr:
                self.file_rules.append((r, pats, hdr))
        self.exceptions, exc_problems = validate_exceptions(policy)
        self.problems += exc_problems
        self.excepted_ids = {e["id"] for e in self.exceptions}

    def _rules(self, key):
        out = []
        for r in self.p.get(key, []) or []:
            rx = safe_compile(r.get("regex", ""), self.problems, "%s %s" % (key, r.get("id", "?")))
            if rx is not None:
                out.append((r, rx))
        return out

    def strict(self, path):
        return bool(path) and glob_match(path, self.p.get("strict_paths", []))

    # -- vendors
    def _compile_vendors(self):
        self._vendor_rx = []
        imp = r"(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)"
        for name, v in (self.p.get("vendors", {}) or {}).items():
            for pkg in v.get("packages", []):
                quoted = r"[\"']" + re.escape(pkg) + (r"[^\"']+[\"']" if pkg.endswith("/") else r"(?:/[^\"']*)?[\"']")
                self._vendor_rx.append((name, "import " + pkg.rstrip("/"), pkg, "code", re.compile(imp + quoted, re.M)))
                self._vendor_rx.append((name, "dependency " + pkg.rstrip("/"), pkg, "package.json", re.compile(quoted + r"\s*:")))
            for mod in v.get("py_modules", []):
                m = re.escape(mod)
                self._vendor_rx.append((name, "import " + mod, mod, "code", re.compile(r"^\s*(?:from\s+%s(?:\.|\s)|import\s+%s\b)" % (m, m), re.M)))
                self._vendor_rx.append((name, "dependency " + mod, mod, "pydeps", re.compile(r"^\s*[\"']?%s\b" % m, re.M | re.I)))
            for dom in v.get("domains", []):
                self._vendor_rx.append((name, "host " + dom, dom, "any",
                    re.compile(r"(?:https?://|wss?://|[\"'`@])(?:[A-Za-z0-9-]+\.)*" + re.escape(dom) + r"(?![A-Za-z0-9-])")))

    def vendor_hits(self, path, text):
        if not hasattr(self, "_vendor_rx"):
            self._compile_vendors()
        base = os.path.basename(path or "")
        kind = "package.json" if base == "package.json" else ("pydeps" if base in ("requirements.txt", "pyproject.toml", "Pipfile") else "code")
        low = text.lower()
        hits = []
        for name, how, needle, applies, rx in self._vendor_rx:
            if applies not in ("any", kind):
                continue
            if (needle.lower() not in low) if applies == "pydeps" else (needle not in text):
                continue
            if rx.search(text):
                hits.append((name, how))
        return hits

    def vendor_applies(self, path):
        if not path:
            return True
        if glob_match(path, self.p.get("vendor_exempt_paths", [])):
            return False
        base = os.path.basename(path)
        if base in self.p.get("vendor_check_files", []):
            return True
        exts = self.p.get("vendor_check_extensions")
        return exts is None or any(base.endswith(e) for e in exts)

    def vendor_findings(self, path, added_lines, removed_text=""):
        out = []
        if not self.vendor_applies(path):
            return out
        added_text = "\n".join(t for _, t in added_lines)
        seen = set()
        before = set(self.vendor_hits(path, removed_text)) if removed_text else set()
        for name, how in self.vendor_hits(path, added_text):
            if (name, how) in before or (name, how) in seen:
                continue
            seen.add((name, how))
            v = self.p["vendors"][name]
            status = v.get("status", "unverified")
            needle = how.split(" ", 1)[1]
            ln, mark = next(((ln, self.mark_of(t)) for ln, t in added_lines if needle in t), (None, None))
            allowed_paths = v.get("allowed_paths")
            if status == "baa":
                continue
            if status == "no_phi":
                if allowed_paths and path and not glob_match(path, allowed_paths):
                    out.append(Finding("VENDOR-NO-PHI", "deny",
                        "%s (%s) may not receive PHI and is only allowed in %s. Move it there or get it approved." %
                        (name, how, ", ".join(allowed_paths)), path, ln, mark))
                continue
            if status == "no_baa":
                out.append(Finding("VENDOR-NO-BAA", "deny",
                    "%s (%s) is marked no_baa in this repo's policy. Don't use it in this app; pick a vendor marked 'baa' in %s." % (name, how, REPO_POLICY_NAME), path, ln, mark))
                continue
            out.append(Finding("VENDOR-UNVERIFIED", self.p.get("unverified_action", "ask"),
                "%s (%s) has no confirmed BAA status for this repo. The policy owner checks the agreement and records the status in %s before it gets any data." % (name, how, REPO_POLICY_NAME), path, ln, mark))
        return out

    def mark_of(self, text):
        m = self.marker_re.search(text)
        if not m:
            return None
        return m.group(1) or ""

    # -- line checks; lines = [(lineno or None, text)]
    def line_findings(self, path, lines, synthetic=False, all_scopes=False):
        """synthetic: the whole file carries the synthetic marker.
        all_scopes: apply strict-only PHI patterns everywhere (prompts, egress)."""
        out = []
        strict = self.strict(path)
        ext = os.path.splitext(path or "")[1].lower()
        is_source = ext in self.p.get("source_extensions", [])
        syn_domains = [d.lower() for d in self.p.get("synthetic_email_domains", [])]
        contact = self.p.get("strict_contact_rules", {}) or {}
        norm = [(ln, normalize(t)) for ln, t in lines]
        for idx, (ln, text) in enumerate(norm):
            mark = self.mark_of(text)
            for r, rx in self.secrets:
                if r.get("skip_strict") and strict:
                    continue
                if rx.search(text):
                    out.append(Finding(r["id"], r.get("action", "deny"),
                        "looks like a credential (value hidden). Keep secrets in the secret manager or an ignored .env file.", path, ln, mark))
            for r, rx in self.phi:
                if r.get("scope") == "strict" and not strict and not all_scopes:
                    continue
                if synthetic and r.get("synthetic_ok"):
                    continue
                if rx.search(text):
                    out.append(Finding(r["id"], r.get("action", "deny"),
                        "%s (value hidden). Use synthetic data; real identifiers never go in code, tests, docs or commands." % r.get("description", "PHI-shaped value"), path, ln, mark))
            if strict and contact.get("email") and not synthetic:
                for m in self.email_re.finditer(text):
                    dom = m.group(1).lower()
                    if not any(dom == d or dom.endswith("." + d) for d in syn_domains):
                        out.append(Finding("PHI-EMAIL-FIXTURE", contact["email"],
                            "real-looking email in test or seed data (value hidden). Use @example.com or a .test domain.", path, ln, mark))
                        break
            if strict and contact.get("phone") and not synthetic:
                for m in self.phone_re.finditer(text):
                    if not (m.group(2) == "555" and m.group(3).startswith("01")):
                        out.append(Finding("PHI-PHONE-FIXTURE", contact["phone"],
                            "real-looking phone number in test or seed data (value hidden). Use 555-01xx numbers.", path, ln, mark))
                        break
            if is_source and self.log_call and self.log_risky:
                m = self.log_call.search(text)
                if m:
                    args = text[m.end():]
                    # a call split over several lines: read on until the parentheses close
                    depth, k = args.count("(") - args.count(")"), idx + 1
                    while depth > -1 and k < len(norm) and k <= idx + 6:
                        nxt_ln, nxt = norm[k]
                        if ln is not None and nxt_ln is not None and nxt_ln != ln + (k - idx):
                            break
                        args += " " + nxt
                        depth += nxt.count("(") - nxt.count(")")
                        k += 1
                    args = strip_string_literals(args)
                    if self.log_safe:
                        args = self.log_safe.sub(" 0 ", args)
                    if self.log_risky.search(args) or (self.log_bare and self.log_bare.search(args)):
                        out.append(Finding("LOG-PHI", (self.p.get("log_rule", {}) or {}).get("action", "deny"),
                            "log or error-tracker call passes a whole object, body or patient field. Log ids, counts, codes and field names only.", path, ln, mark))
            for r, rx in self.custom:
                if path and (not glob_match(path, r.get("paths", ["**/*"])) or glob_match(path, r.get("exclude_paths", []))):
                    continue
                if r.get("skip_strict") and strict:
                    continue
                if rx.search(text):
                    out.append(Finding(r["id"], r.get("action", "deny"), r.get("message", r.get("description", "")), path, ln, mark))
            if mark is not None and path and is_source and not any(f.line == ln and f.path == path for f in out):
                if mark not in self.excepted_ids:
                    out.append(Finding("WAIVER-UNREGISTERED", self.p.get("unregistered_waiver_action", "deny"),
                        "inline waiver doesn't name a registered exception. Waivers are added to 'exceptions' in %s with an approver and an expiry, then referenced as '%s <ID>'." % (REPO_POLICY_NAME, self.marker), path, ln))
        return out

    def file_level_findings(self, path, full_text):
        out = []
        if not path:
            return out
        synthetic = self.synthetic_marker in full_text
        if self.strict(path) and self.fixture_field:
            fm = self.p.get("fixture_marker_rule", {}) or {}
            if self.fixture_field.search(full_text) and not synthetic:
                out.append(Finding("FIXTURE-NOT-MARKED", fm.get("action", "ask"),
                    "test or seed file holds person-shaped fields but doesn't say it is synthetic. Add a '%s' comment or key once the data is confirmed fake." % self.synthetic_marker, path))
        out += self.content_rule_findings(path, full_text, synthetic)
        return out

    def content_rule_findings(self, path, text, synthetic):
        out = []
        text = normalize(text)
        first = next((l for l in text.splitlines() if l.strip()), "")
        for r, pats, hdr in self.file_rules:
            if synthetic and r.get("synthetic_ok"):
                continue
            if pats and all(p.search(text) for p in pats):
                out.append(Finding(r["id"], r.get("action", "ask"), r.get("description", "") + " (values hidden).", path))
            elif hdr and all(p.search(first) for p in hdr):
                out.append(Finding(r["id"], r.get("action", "ask"), r.get("description", "") + " (values hidden).", path))
        return out

    def data_file_findings(self, path):
        out = []
        if not path:
            return out
        for r in self.p.get("data_file_rules", []) or []:
            if glob_match(path, r.get("globs", [])):
                action = r.get("strict_action", r.get("action")) if self.strict(path) else r.get("action", "ask")
                out.append(Finding(r["id"], action, r.get("message", "data file"), path))
                break
        return out

    def protected(self, path, abspath=None):
        if path and glob_match(path, self.p.get("protected_paths", [])):
            return True
        a = abspath or (os.path.join(self.root, path) if path else None)
        if not a:
            return False
        a = os.path.abspath(a)
        home = os.path.expanduser("~")
        if a == PLUGIN_ROOT or a.startswith(PLUGIN_ROOT + os.sep):
            return True
        if a.startswith(os.path.join(home, ".claude", "plugins") + os.sep):
            return True
        if os.path.basename(a) in ("settings.json", "settings.local.json", "managed-settings.json") and os.path.basename(os.path.dirname(a)) == ".claude":
            return True
        return False

    def protected_findings(self, path, abspath=None):
        if self.protected(path, abspath):
            return [Finding("GUARD-CONFIG", "ask",
                "this file holds the HIPAA guardrails or what enforces them (policy, Claude settings, git hooks, CI, CODEOWNERS). Changes go to the policy owner for review.", path)]
        return []

    def path_findings(self, path, writing=False):
        out = []
        if path and self.env_re.search(path) and not self.env_ok_re.search(path):
            if writing and not self.is_git_ignored(path):
                out.append(Finding("ENV-NOT-IGNORED", "deny",
                    "this .env file is not git-ignored. Add it to .gitignore first; commit only .env.example with placeholder values.", path))
        return out

    def is_env(self, path):
        return bool(path) and bool(self.env_re.search(path)) and not self.env_ok_re.search(path)

    def is_git_ignored(self, path):
        try:
            r = subprocess.run(["git", "check-ignore", "-q", path], cwd=self.root,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def ignored(self, path):
        return bool(path) and glob_match(path, self.p.get("ignore_paths", []))

    def check_change(self, path, added_lines, full_text=None, removed_text="", synthetic=None, new_file=False, changing=True):
        """added_lines: [(lineno, text)]; full_text: the file after the change, if known.
        changing=False for a full scan of files as they are (no change to a protected file)."""
        out = self.protected_findings(path) if changing else []
        if new_file:
            out += self.data_file_findings(path)
        if self.ignored(path):
            return out
        out += self.path_findings(path, writing=True)
        if synthetic is None:
            synthetic = full_text is not None and self.synthetic_marker in full_text
        out += self.line_findings(path, added_lines, synthetic=synthetic)
        out += self.vendor_findings(path, [(ln, normalize(t)) for ln, t in added_lines], removed_text)
        if full_text is not None:
            out += self.file_level_findings(path, full_text)
        return out

    # -- reading files: does this file hold patient data?
    def sniff_file(self, rpath, abspath, covered):
        if covered or not abspath or not os.path.isfile(abspath) or self.ignored(rpath):
            return []
        sn = self.p.get("sniff", {}) or {}
        try:
            with open(abspath, "rb") as f:
                head = f.read(int(sn.get("max_bytes", 262144)))
        except Exception:
            return []
        if b"\x00" in head[:4096]:
            return []  # binary; data_file_rules and phi_read_paths cover the risky binary types
        text = head.decode("utf-8", errors="replace")
        if self.synthetic_marker in text:
            return []
        found = set()
        norm = normalize(text)
        single = set(sn.get("single_hit_rules", ["PHI-SSN", "PHI-SSN-LABELED", "PHI-HL7"]))
        need = int(sn.get("min_hits", 3))
        for r, rx in self.phi:
            if r["id"] in single:
                if rx.search(norm):
                    found.add(r["id"])
            elif sum(1 for _ in zip(range(need), rx.finditer(norm))) >= need:
                found.add(r["id"])
        for f in self.content_rule_findings(rpath, text, False):
            found.add(f.rule)
        if not found:
            return []
        action = "ask" if self.strict(rpath) else "deny"
        return [Finding("PHI-READ-CONTENT", action,
            "this file's contents look like patient data (%s; values hidden). Reading it would send them to a model session without a BAA." % ", ".join(sorted(found)), rpath)]

    # -- waivers and exceptions
    def apply_exceptions(self, findings):
        never = self.p.get("never_excepted", [])
        by_id = {e["id"]: e for e in self.exceptions}
        out = []
        d = today()
        for f in findings:
            out.append(f)
            if prefix_match(f.rule, never):
                if f.mark:
                    f.message += " This rule can't be waived."
                continue
            if f.mark is not None and f.path:
                exc = by_id.get(f.mark)
                if exc and exc["_expired"]:
                    out.append(Finding("EXCEPTION-EXPIRED", "warn", "exception %s expired on %s; the finding is active again." % (exc["id"], exc["expires"]), f.path, f.line))
                elif exc and prefix_match(f.rule, exc["rules"]) and glob_match(f.path, exc["paths"]):
                    f.exception = exc["id"]
                    continue
                elif f.rule != "WAIVER-UNREGISTERED":
                    out.append(Finding("WAIVER-UNREGISTERED", self.p.get("unregistered_waiver_action", "deny"),
                        "inline waiver %s doesn't cover %s here. Register an exception for this rule and path in %s." % ("'%s'" % f.mark if f.mark else "without an id", f.rule, REPO_POLICY_NAME), f.path, f.line))
                    continue
            for exc in self.exceptions:
                if exc.get("scope") == "path" and not exc["_expired"] and f.path and prefix_match(f.rule, exc["rules"]) and glob_match(f.path, exc["paths"]):
                    f.exception = exc["id"]
                    break
        return dedupe(out)


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        k = (f.rule, f.path, f.line, f.exception, f.message if f.line is None else "")
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def validate_exceptions(policy):
    good, problems = [], []
    d = today()
    seen = set()
    for i, e in enumerate(policy.get("exceptions", []) or []):
        where = "exceptions[%d]" % i
        if not isinstance(e, dict):
            problems.append("%s is not an object" % where)
            continue
        eid = e.get("id")
        if not eid or not ID_RE.fullmatch(str(eid)):
            problems.append("%s has no valid id" % where)
            continue
        if eid in seen:
            problems.append("exception %s is listed twice" % eid)
            continue
        seen.add(eid)
        missing = [k for k in ("rules", "paths", "reason", "approver", "approved_on", "expires") if not e.get(k)]
        if missing:
            problems.append("exception %s is missing %s" % (eid, ", ".join(missing)))
            continue
        ap, ex = parse_date(e["approved_on"]), parse_date(e["expires"])
        if not ap or not ex:
            problems.append("exception %s needs approved_on and expires as YYYY-MM-DD" % eid)
            continue
        if ex < ap:
            problems.append("exception %s expires before it was approved" % eid)
            continue
        if (ex - ap).days > 366:
            problems.append("exception %s runs longer than a year; renew it instead" % eid)
            continue
        if prefix_match(eid, []) or any(prefix_match(r, policy.get("never_excepted", [])) for r in e["rules"]):
            problems.append("exception %s names a rule that can't be excepted" % eid)
            continue
        e2 = dict(e)
        e2["_expired"] = d > ex
        e2["_days_left"] = (ex - d).days
        e2.setdefault("scope", "line")
        good.append(e2)
    return good, problems


def validate_config(policy, root):
    """Problems with the repo's policy, as findings (CI fails on deny)."""
    out = []
    checker = Checker(policy, root)
    for p in checker.problems:
        out.append(Finding("CONFIG-INVALID", "deny", p, REPO_POLICY_NAME))
    raw = policy.get("_repo_raw")
    if raw is None:
        return out, checker
    for k in raw:
        base = k[:-1] if k.endswith("+") else k
        if not k.startswith("_") and base not in KNOWN_KEYS:
            out.append(Finding("CONFIG-UNKNOWN-KEY", "warn", "unknown key '%s' is ignored (typo?)." % k, REPO_POLICY_NAME))
    sv = raw.get("schema_version")
    if sv is not None and sv > SCHEMA_VERSION:
        out.append(Finding("CONFIG-PLUGIN-OLD", "deny", "this config uses schema %s; this plugin understands %s. Update the plugin." % (sv, SCHEMA_VERSION), REPO_POLICY_NAME))
    req = raw.get("requires_plugin")
    if req:
        m = re.match(r"\s*>=\s*(\S+)", str(req))
        if m and vtuple(PLUGIN_VERSION) < vtuple(m.group(1)):
            out.append(Finding("CONFIG-PLUGIN-OLD", "deny", "this repo requires plugin %s; installed is %s. Update the plugin." % (req, PLUGIN_VERSION), REPO_POLICY_NAME))
    if raw.get("policy_version") is None:
        out.append(Finding("CONFIG-UNVERSIONED", "warn", "add policy_version and a change_log entry so policy changes have an approver and a date.", REPO_POLICY_NAME))
    for i, c in enumerate(raw.get("change_log", []) or []):
        missing = [k for k in ("version", "date", "approver", "summary") if not c.get(k)]
        if missing:
            out.append(Finding("CONFIG-INVALID", "deny", "change_log[%d] is missing %s" % (i, ", ".join(missing)), REPO_POLICY_NAME))
    warn_days = int(policy.get("exception_expiry_warning_days", 14))
    for e in checker.exceptions:
        if e["_expired"]:
            out.append(Finding("EXCEPTION-EXPIRED", "warn", "exception %s expired on %s." % (e["id"], e["expires"]), REPO_POLICY_NAME))
        elif e["_days_left"] <= warn_days:
            out.append(Finding("EXCEPTION-EXPIRING", "warn", "exception %s expires in %d day(s)." % (e["id"], e["_days_left"]), REPO_POLICY_NAME))
    for name, v in (policy.get("vendors", {}) or {}).items():
        st = v.get("status", "unverified")
        if st not in ("baa", "no_phi", "no_baa", "unverified"):
            out.append(Finding("CONFIG-INVALID", "deny", "vendor %s has unknown status '%s'" % (name, st), REPO_POLICY_NAME))
    staged = git(["ls-files", "-s", "--", ".githooks/pre-commit"], root, check=False).split()
    if staged and staged[0] != "100755":
        out.append(Finding("GUARD-HOOK-NOT-EXECUTABLE", "warn",
            ".githooks/pre-commit is committed without the executable bit, so git silently skips it. Run: git update-index --chmod=+x .githooks/pre-commit", ".githooks/pre-commit"))
    if policy.get("mode") not in ("enforce", "warn"):
        out.append(Finding("CONFIG-INVALID", "deny", "mode must be 'enforce' or 'warn'", REPO_POLICY_NAME))
    return out, checker


# ================================================================ PreToolUse

def added_lines_between(old, new):
    old_set = set(old.splitlines())
    return [(i + 1, l) for i, l in enumerate(new.splitlines()) if l not in old_set]


def string_values(obj, limit=200000):
    """All string values in a tool input, depth first, capped."""
    out, total = [], 0
    stack = [obj]
    while stack and total < limit:
        o = stack.pop()
        if isinstance(o, str):
            out.append(o)
            total += len(o)
        elif isinstance(o, dict):
            stack.extend(o.values())
        elif isinstance(o, (list, tuple)):
            stack.extend(o)
    return out


EGRESS_TOOLS = ("WebFetch", "WebSearch", "Task", "Agent")
PATH_KEYS = ("file_path", "path", "filepath", "filename", "file", "notebook_path", "directory", "dir")


def egress_findings(checker, tool, tin, covered):
    """Patient identifiers in what a tool sends somewhere else: a URL, a search, a subagent, an MCP server."""
    out = []
    lines = [(None, s) for s in string_values(tin)]
    found = checker.line_findings(None, lines, all_scopes=True)
    phi = sorted({f.rule for f in found if f.rule.startswith("PHI-")})
    sec = sorted({f.rule for f in found if f.rule.startswith("SECRET-") and f.action == "deny"})
    to_model_only = tool in ("Task", "Agent")
    if phi and not (to_model_only and covered):
        out.append(Finding("PHI-EGRESS", "deny",
            "this %s call carries values shaped like patient identifiers (%s; values hidden). They would leave for a service without a BAA." % (tool, ", ".join(phi)), tool))
    if sec and not to_model_only:
        out.append(Finding("SECRET-EGRESS", "deny", "this %s call carries a credential (%s; value hidden)." % (tool, ", ".join(sec)), tool))
    return out


def check_tool(tool, tin, checker, policy, root, cwd):
    out = []
    covered = covered_runtime(policy)

    if tool.startswith("mcp__"):
        is_phi_tool = any(re.search(pat, tool) for pat in policy.get("phi_mcp_tools", []) or [])
        if is_phi_tool and not covered:
            out.append(Finding("MCP-PHI-TOOL", "deny",
                "this tool returns patient data and this session is not on a BAA-covered model runtime. Use the synthetic org, or run the work in a covered (Bedrock) session.", tool))
        if not (is_phi_tool and covered):
            out += egress_findings(checker, tool, tin, covered)
        for k in PATH_KEYS:
            v = tin.get(k) if isinstance(tin, dict) else None
            if isinstance(v, str) and v:
                rp = rel(os.path.join(cwd, v), root)
                if dir_match(rp, policy.get("phi_read_paths", [])) and not covered:
                    out.append(Finding("PHI-READ", "deny", "this tool call points at a path marked as holding PHI.", rp))
        return out

    if tool in EGRESS_TOOLS:
        return egress_findings(checker, tool, tin, covered)

    path = tin.get("file_path") or tin.get("notebook_path") or tin.get("path")
    apath = os.path.join(cwd, path) if path else None
    rpath = rel(apath, root) if path else None

    if tool in ("Read", "Grep", "Glob"):
        targets = [rpath] if rpath else []
        if tool == "Glob" and tin.get("pattern"):
            targets.append(rel(os.path.join(apath or cwd, tin["pattern"]), root))
        if tool == "Grep" and tin.get("glob"):
            targets.append(rel(os.path.join(apath or cwd, tin["glob"]), root))
        if not covered:
            for t in targets:
                if dir_match(t, policy.get("phi_read_paths", [])):
                    out.append(Finding("PHI-READ", "deny",
                        "this path is marked as holding PHI. Reading it would send patient data to a model session without a BAA.", t))
                    return out
            if rpath and checker.is_env(rpath):
                out.append(Finding("ENV-READ", "ask", "reading a .env file sends its secrets into the session. Read .env.example instead, or ask for the one value you need.", rpath))
            if apath and os.path.isfile(apath):
                out += checker.sniff_file(rpath, apath, covered)
        return out

    if tool == "Write":
        new = tin.get("content", "")
        old = ""
        exists = bool(apath and os.path.exists(apath))
        if exists:
            try:
                with open(apath, errors="replace") as f:
                    old = f.read()
            except Exception:
                old = ""
        out = checker.protected_findings(rpath, apath) + checker.check_change(rpath, added_lines_between(old, new), full_text=new, removed_text=old, new_file=not exists)
        return out

    if tool in ("Edit", "MultiEdit"):
        edits = tin.get("edits") or [{"old_string": tin.get("old_string", ""), "new_string": tin.get("new_string", ""), "replace_all": tin.get("replace_all")}]
        full = None
        if apath and os.path.exists(apath):
            try:
                with open(apath, errors="replace") as f:
                    full = f.read()
                for e in edits:
                    full = full.replace(e.get("old_string", ""), e.get("new_string", ""), -1 if e.get("replace_all") else 1)
            except Exception:
                full = None
        synthetic = full is not None and checker.synthetic_marker in full
        out += checker.protected_findings(rpath, apath)
        for e in edits:
            out += checker.check_change(rpath, added_lines_between(e.get("old_string", ""), e.get("new_string", "")),
                                        removed_text=e.get("old_string", ""), synthetic=synthetic)
        if full is not None and not checker.ignored(rpath):
            out += checker.file_level_findings(rpath, full)
        return out

    if tool == "NotebookEdit":
        src = tin.get("new_source", "")
        return checker.protected_findings(rpath, apath) + checker.check_change(rpath, [(None, l) for l in src.splitlines()])

    if tool == "Bash":
        return check_command(tin.get("command", ""), checker, policy, root, cwd, covered)

    return out


READ_CMDS = {"cat", "head", "tail", "less", "more", "grep", "rg", "egrep", "fgrep", "awk", "sed", "cut", "sort", "uniq",
             "jq", "xxd", "od", "strings", "nl", "wc", "column", "csvlook", "csvcut", "sqlite3", "bat", "view", "base64", "zcat", "gzip", "tar", "zip", "unzip", "cp", "scp", "rsync", "diff", "file", "iconv", "split", "openssl", "gpg"}
SHELLS = {"bash", "sh", "zsh", "dash", "source", "."}
SCRIPT_RUNNERS = {"python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "tsx", "ts-node"}
SEPARATORS = {"&&", "||", ";", "|", "&", "|&"}


def split_segments(tokens):
    segs, cur = [], []
    for t in tokens:
        if t in SEPARATORS:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def heredocs(cmd):
    """[(target or None, body)] for `... > target <<EOF ... EOF` and `tee target <<EOF`."""
    out = []
    for m in re.finditer(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n(.*?)\n\s*\2\s*(?:\n|$)", cmd, re.S):
        head = cmd[max(0, cmd.rfind("\n", 0, m.start()) + 1):m.start() + len(m.group(0).split("\n", 1)[0])]
        tgt = re.search(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*([^\s<>|;&]+)", head)
        out.append((tgt.group(1).strip("'\"") if tgt else None, m.group(3)))
    return out


def write_targets(cmd, segments):
    targets = set()
    for m in re.finditer(r"(?<![<>&0-9])(?:[12]?>>?|&>>?)\s*([^\s<>|;&()]+)", cmd):
        t = m.group(1).strip("'\"")
        if t and not t.startswith("&") and t not in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            targets.add(t)
    for seg in segments:
        if not seg:
            continue
        exe = os.path.basename(seg[0])
        args = [a for a in seg[1:] if not a.startswith("-")]
        if exe == "tee":
            targets.update(args)
        elif exe in ("cp", "mv", "install", "rsync", "ln") and len(args) >= 2:
            targets.add(args[-1])
        elif exe == "sed" and any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in seg[1:]):
            targets.update(a for a in args[1:])
        elif exe in ("touch", "truncate", "dd"):
            targets.update(a.split("=", 1)[1] if a.startswith("of=") else a for a in args if "=" not in a or a.startswith("of="))
    for m in re.finditer(r"open\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"][wax]", cmd):
        targets.add(m.group(1))
    for m in re.finditer(r"writeFile(?:Sync)?\(\s*['\"`]([^'\"`]+)['\"`]", cmd):
        targets.add(m.group(1))
    return targets


def path_candidates(token):
    out = {token}
    for m in re.finditer(r"[\w~./@-]*[/.][\w~./@*-]+", token):
        out.add(m.group(0))
    return {t.strip("'\"") for t in out if t and len(t) < 400}


def check_command(cmd, checker, policy, root, cwd, covered, depth=0):
    out = []
    ncmd = normalize(cmd)
    # PHI or secrets typed into a command end up in shell history, logs and transcripts
    for f in checker.line_findings(None, [(None, ncmd)], all_scopes=True):
        if f.rule.startswith(("PHI-", "SECRET-")):
            f.message = f.message.split(" (value hidden)")[0] + " in a shell command (value hidden). Don't put identifiers or keys on the command line."
            f.mark = None  # a marker in a command never waives anything
            out.append(f)
    for r in policy.get("blocked_commands", []) or []:
        try:
            if re.search(r["regex"], ncmd):
                out.append(Finding(r["id"], r.get("action", "deny"), r.get("message", ""), None))
        except re.error:
            pass
    try:
        tokens = shlex.split(ncmd, posix=True, comments=False)
    except ValueError:
        tokens = ncmd.split()
    lexer_tokens = []
    for t in tokens:  # shlex keeps "a&&b" together when unspaced; split on separators too
        lexer_tokens += [x for x in re.split(r"(&&|\|\||;|\|)", t) if x]
    segments = split_segments(lexer_tokens)
    bases = [cwd]
    for seg in segments:
        if seg and seg[0] in ("cd", "pushd") and len(seg) > 1:
            bases.append(os.path.join(cwd, seg[1]))
            for b in list(bases[1:]):
                bases.append(os.path.join(b, seg[1]))
    phi_paths = policy.get("phi_read_paths", []) or []
    # touching PHI paths from the shell
    if not covered:
        hit = None
        for t in lexer_tokens:
            for cand in path_candidates(t):
                if cand.startswith("-"):
                    continue
                for b in bases:
                    if not ("/" in cand or "." in cand or os.path.exists(os.path.join(b, cand))):
                        continue
                    rp = rel(os.path.join(b, os.path.expanduser(cand)), root)
                    if dir_match(rp, phi_paths):
                        hit = rp
                        break
                if hit:
                    break
            if hit:
                break
        if hit:
            out.append(Finding("PHI-READ", "deny", "the command touches a path marked as holding PHI.", hit))
        # file contents read by the command
        sniffed = 0
        max_files = int((policy.get("sniff", {}) or {}).get("max_files_per_command", 6))
        for seg in segments:
            if not seg or os.path.basename(seg[0]) not in READ_CMDS:
                continue
            for a in seg[1:]:
                if a.startswith("-") or sniffed >= max_files:
                    continue
                ap = os.path.join(cwd, os.path.expanduser(a))
                if os.path.isfile(ap):
                    sniffed += 1
                    rp = rel(ap, root)
                    if checker.is_env(rp) and os.path.basename(seg[0]) not in ("cp", "rsync", "scp"):
                        out.append(Finding("ENV-READ", "ask", "this command prints a .env file's secrets into the session.", rp))
                    out += checker.sniff_file(rp, ap, covered)
    # files the command writes
    for t in write_targets(ncmd, segments):
        ap = os.path.join(cwd, os.path.expanduser(t))
        rp = rel(ap, root)
        out += checker.protected_findings(rp, ap)
        if not os.path.exists(ap):
            out += checker.data_file_findings(rp)
        if checker.is_env(rp) and not checker.is_git_ignored(rp):
            out += checker.path_findings(rp, writing=True)
    for tgt, body in heredocs(ncmd):
        if tgt:
            ap = os.path.join(cwd, os.path.expanduser(tgt))
            rp = rel(ap, root)
            for f in checker.check_change(rp, [(i + 1, l) for i, l in enumerate(body.splitlines())], full_text=body):
                if not f.rule.startswith(("PHI-", "SECRET-")) or f.rule.startswith(("PHI-EMAIL", "PHI-PHONE", "PHI-DOB", "PHI-MBI", "PHI-FHIR", "PHI-CSV")):
                    f.mark = None
                    out.append(f)
    # running a script: check what the script does, one level deep
    if depth == 0:
        for seg in segments:
            if not seg:
                continue
            exe = os.path.basename(seg[0])
            script = None
            if exe in SHELLS or exe in SCRIPT_RUNNERS:
                script = next((a for a in seg[1:] if not a.startswith("-")), None)
                if exe in SCRIPT_RUNNERS and any(a in ("-c", "-e", "--eval") for a in seg[1:]):
                    script = None
            elif seg[0].startswith("./") or seg[0].endswith((".sh", ".py")):
                script = seg[0]
            if not script:
                continue
            ap = os.path.join(cwd, script)
            if os.path.isfile(ap) and os.path.getsize(ap) < 262144:
                try:
                    with open(ap, errors="replace") as f:
                        body = f.read()
                except Exception:
                    continue
                sub = check_command(body, checker, policy, root, os.path.dirname(ap), covered, depth=1) if (exe in SHELLS or ap.endswith(".sh")) else []
                if exe in SCRIPT_RUNNERS or ap.endswith(".py"):
                    for lit in re.findall(r"['\"`]([^'\"`\n]{2,300})['\"`]", body):
                        rp = rel(os.path.join(os.path.dirname(ap), lit), root)
                        if not covered and ("/" in lit or "." in lit) and dir_match(rp, phi_paths):
                            sub.append(Finding("PHI-READ", "deny", "the script this command runs refers to a path marked as holding PHI.", rel(ap, root)))
                            break
                        if checker.protected(rp) and re.search(r"open\([^)]*['\"][wa]|writeFile|unlink|remove|rmtree", body):
                            sub.append(Finding("GUARD-CONFIG", "ask", "the script this command runs may change a guardrails file.", rel(ap, root)))
                            break
                for f in sub:
                    f.message = "(in %s) %s" % (rel(ap, root), f.message)
                out += sub
    # sending data to vendors from the shell
    if re.search(r"\b(curl|wget|http|https|httpie|xh)\b", ncmd) and re.search(r"(\s-d\b|--data|\s-F\b|--form|--upload-file|\s-T\b|-X\s*(POST|PUT|PATCH)|\s--json\b)", ncmd):
        for f in checker.vendor_findings(None, [(None, ncmd)]):
            f.message = "sending data from the shell: " + f.message
            out.append(f)
    # staging env files and data files
    if re.search(r"\bgit\s+add\b", ncmd):
        for t in lexer_tokens:
            if checker.is_env(t):
                out.append(Finding("ENV-STAGED", "deny", "don't commit .env files; commit .env.example with placeholders.", t))
    # commits: check what would be recorded
    if re.search(r"\bgit\b[^|;&]*\bcommit\b", ncmd) and depth == 0:
        include_unstaged = bool(re.search(r"\bgit\b[^|;&]*\bcommit\b[^|;&]*\s(-a\b|--all\b|-[a-zA-Z]*a[a-zA-Z]*\b)", ncmd))
        out += staged_findings(checker, root, include_unstaged)
    bf = re.search(r"--body-file\s+(\S+)", ncmd)
    if bf and os.path.isfile(os.path.join(cwd, bf.group(1))):
        with open(os.path.join(cwd, bf.group(1)), errors="replace") as f:
            body = f.read()
        for f2 in checker.line_findings(None, [(i + 1, l) for i, l in enumerate(body.splitlines())], all_scopes=True):
            if f2.rule.startswith(("PHI-", "SECRET-")):
                f2.path, f2.mark = bf.group(1), None
                out.append(f2)
    return out


# ================================================================ git diffs

def git(args, root, check=True):
    r = subprocess.run(["git"] + args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if r.returncode != 0 and check:
        raise RuntimeError("git %s failed: %s" % (" ".join(args[:3]), r.stderr.decode(errors="replace").strip()[:200]))
    return r.stdout.decode(errors="replace")


def parse_diff(diff):
    """{path: {"added": [(lineno, text)], "removed": [text], "new": bool}}."""
    files, cur, newline, is_new = {}, None, 0, False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            cur, is_new = None, False
        elif line.startswith("new file mode"):
            is_new = True
        elif line.startswith("--- "):
            if line[4:] == "/dev/null":
                is_new = True
        elif line.startswith("+++ "):
            p = line[4:]
            if p == "/dev/null":
                cur = None
                continue
            cur = p[2:] if p.startswith("b/") else p
            files.setdefault(cur, {"added": [], "removed": [], "new": is_new})
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            newline = int(m.group(1)) if m else 0
        elif cur is None:
            continue
        elif line.startswith("+"):
            files[cur]["added"].append((newline, line[1:]))
            newline += 1
        elif line.startswith("-"):
            files[cur]["removed"].append(line[1:])
        elif line.startswith(" "):
            newline += 1
    return files


def diff_findings(checker, diff, read_full, added_files=()):
    out = []
    parsed = parse_diff(diff)
    for path, d in parsed.items():
        full = read_full(path)
        out += checker.check_change(path, d["added"], full_text=full, removed_text="\n".join(d["removed"]),
                                    new_file=d["new"] or path in added_files)
    for path in added_files:  # binary files never show up as text hunks
        if path not in parsed:
            out += checker.protected_findings(path) + checker.data_file_findings(path)
    return out


def staged_findings(checker, root, include_unstaged=False):
    try:
        diff = git(["diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-renames"], root)
        if include_unstaged:
            diff += "\n" + git(["diff", "-U0", "--no-color", "--no-ext-diff", "--no-renames"], root)
        names = git(["diff", "--cached", "--name-only", "--no-renames"], root).split("\n")
        added = set(x for x in git(["diff", "--cached", "--name-only", "--no-renames", "--diff-filter=A"], root).split("\n") if x)
    except Exception as e:
        return [Finding("GIT", "warn", "couldn't read the staged diff (%s); CI will still check." % str(e)[:120])]
    out = []
    for n in names:
        if n and checker.is_env(n):
            out.append(Finding("ENV-STAGED", "deny", "a .env file is staged. Unstage it (git restore --staged) and keep it ignored.", n))

    def read_index(path):
        try:
            return git(["show", ":" + path], root)
        except Exception:
            return None
    return out + diff_findings(checker, diff, read_index, added)


# ================================================================ policy change control (CI)

def rule_actions(policy):
    out = {}
    for key in ("phi_patterns", "secret_patterns", "custom_rules", "blocked_commands", "data_file_rules", "file_level_rules"):
        for r in policy.get(key, []) or []:
            out[r.get("id")] = r.get("action", "deny")
    out["LOG-PHI"] = (policy.get("log_rule", {}) or {}).get("action", "deny")
    out["FIXTURE-NOT-MARKED"] = (policy.get("fixture_marker_rule", {}) or {}).get("action", "ask")
    for k, v in ((policy.get("strict_contact_rules", {}) or {}).items()):
        out["CONTACT-" + k] = v
    return out


def loosenings(old, new):
    """Ways the new merged policy is weaker than the old one. Returns readable lines, no values."""
    out = []
    if old.get("mode") == "enforce" and new.get("mode") != "enforce":
        out.append("mode changed from enforce to %s" % new.get("mode"))
    if not (old.get("runtime", {}) or {}).get("bedrock_is_baa_covered") and (new.get("runtime", {}) or {}).get("bedrock_is_baa_covered"):
        out.append("runtime.bedrock_is_baa_covered turned on (Bedrock sessions may now read PHI)")
    rank = {"no_baa": 0, "unverified": 1, "no_phi": 2, "baa": 3}
    ov, nv = old.get("vendors", {}) or {}, new.get("vendors", {}) or {}
    for name in sorted(set(ov) | set(nv)):
        a, b = (ov.get(name) or {}).get("status", "unverified"), (nv.get(name) or {}).get("status", "unverified")
        if rank.get(b, 1) > rank.get(a, 1):
            out.append("vendor %s: %s -> %s" % (name, a, b))
        oa, na = set((ov.get(name) or {}).get("allowed_paths", []) or []), set((nv.get(name) or {}).get("allowed_paths", []) or [])
        if b == "no_phi" and na - oa:
            out.append("vendor %s: allowed_paths widened" % name)
        op, np_ = set((ov.get(name) or {}).get("packages", []) or []), set((nv.get(name) or {}).get("packages", []) or [])
        if op - np_:
            out.append("vendor %s: stopped matching %d package name(s)" % (name, len(op - np_)))
    oe = {e.get("id"): e for e in old.get("exceptions", []) or [] if isinstance(e, dict)}
    for e in new.get("exceptions", []) or []:
        if not isinstance(e, dict):
            continue
        prev = oe.get(e.get("id"))
        if prev is None:
            out.append("exception %s added (approver: %s, expires %s)" % (e.get("id"), e.get("approver", "?"), e.get("expires", "?")))
        elif str(e.get("expires")) > str(prev.get("expires")) or set(e.get("rules", [])) - set(prev.get("rules", [])) or set(e.get("paths", [])) - set(prev.get("paths", [])):
            out.append("exception %s widened or extended" % e.get("id"))
    for key, word in (("ignore_paths", "added"), ("vendor_exempt_paths", "added")):
        added = set(new.get(key, []) or []) - set(old.get(key, []) or [])
        if added:
            out.append("%s: %d pattern(s) %s" % (key, len(added), word))
    for key in ("strict_paths", "phi_read_paths", "phi_mcp_tools", "always_enforce", "never_excepted", "protected_paths"):
        removed = set(old.get(key, []) or []) - set(new.get(key, []) or [])
        if removed:
            out.append("%s: %d entr(y/ies) removed" % (key, len(removed)))
    oa, na = rule_actions(old), rule_actions(new)
    for rid, act in sorted(oa.items()):
        if rid not in na:
            out.append("rule %s removed" % rid)
        elif SEVERITY.get(na[rid], 0) < SEVERITY.get(act, 0):
            out.append("rule %s: %s -> %s" % (rid, act, na[rid]))
    if SEVERITY.get(new.get("unverified_action", "ask"), 0) < SEVERITY.get(old.get("unverified_action", "ask"), 0):
        out.append("unverified_action: %s -> %s" % (old.get("unverified_action"), new.get("unverified_action")))
    if old.get("fail_closed") and not new.get("fail_closed"):
        out.append("fail_closed turned off")
    if (old.get("evidence", {}) or {}).get("enabled", True) and not (new.get("evidence", {}) or {}).get("enabled", True):
        out.append("evidence logging turned off")
    if set((old.get("ci", {}) or {}).get("fail_on", ["deny"])) - set((new.get("ci", {}) or {}).get("fail_on", ["deny"])):
        out.append("ci.fail_on narrowed")
    if SEVERITY.get(new.get("unregistered_waiver_action", "deny"), 0) < SEVERITY.get(old.get("unregistered_waiver_action", "deny"), 0):
        out.append("unregistered_waiver_action weakened")
    return out


def policy_change_findings(root, base, head_policy):
    """When a PR changes the repo policy, require a recorded, approved version bump and list what got looser."""
    out, summary = [], {"changed": False, "loosened": []}
    summary["_old_policy"] = None
    changed = git(["diff", "--name-only", "--no-renames", base + "...HEAD", "--", REPO_POLICY_NAME], root, check=False).strip()
    if not changed:
        return out, summary
    summary["changed"] = True
    old_text = git(["show", "%s:%s" % (git(["merge-base", base, "HEAD"], root).strip(), REPO_POLICY_NAME)], root, check=False)
    old_policy = load_policy(root, repo_text=old_text if old_text.strip() else None)
    old_raw = old_policy.get("_repo_raw") or {}
    new_raw = head_policy.get("_repo_raw") or {}
    ov, nv = old_raw.get("policy_version"), new_raw.get("policy_version")
    entry = next((c for c in new_raw.get("change_log", []) or [] if isinstance(c, dict) and str(c.get("version")) == str(nv)), None)
    if not nv or nv == ov or vtuple(nv) <= vtuple(ov or "0"):
        out.append(Finding("POLICY-CHANGE-UNRECORDED", "deny",
            "the policy changed but policy_version wasn't raised (was %s, now %s). Bump it and add a change_log entry." % (ov or "unset", nv or "unset"), REPO_POLICY_NAME))
    elif not entry or not all(entry.get(k) for k in ("date", "approver", "summary")):
        out.append(Finding("POLICY-CHANGE-UNRECORDED", "deny",
            "policy_version %s has no change_log entry with date, approver and summary." % nv, REPO_POLICY_NAME))
    summary["from"], summary["to"] = ov, nv
    summary["approver"] = entry.get("approver") if entry else None
    loose = loosenings(old_policy, head_policy)
    summary["loosened"] = loose
    summary["_old_policy"] = old_policy
    for l in loose:
        out.append(Finding("POLICY-LOOSENED", "warn", l + ". Needs the policy owner's review (CODEOWNERS).", REPO_POLICY_NAME))
    return out, summary


# ================================================================ evidence

def evidence_dir(policy, root):
    ev = policy.get("evidence", {}) or {}
    base = os.environ.get("HIPAA_GUARDRAILS_EVIDENCE_DIR") or ev.get("dir")
    if base:
        base = os.path.expanduser(base)
        if not os.path.isabs(base):
            base = os.path.join(root, base)
        return base
    # one place for hooks and the git pre-commit hook alike, so a repo has one chain per machine
    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    top = os.path.join(cfg, "hipaa-guardrails", "evidence")
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(root.rstrip("/")) or "repo")
    return os.path.join(top, "%s-%s" % (slug, hashlib.sha256(os.path.abspath(root).encode()).hexdigest()[:8]))


_REPO_INFO = {}


def repo_info(root):
    if root in _REPO_INFO:
        return _REPO_INFO[root]
    info = {"name": os.path.basename(root.rstrip("/"))}
    for key, args in (("commit", ["rev-parse", "HEAD"]), ("branch", ["rev-parse", "--abbrev-ref", "HEAD"]), ("remote", ["remote", "get-url", "origin"])):
        try:
            v = git(args, root, check=False).strip()
            if key == "remote":
                v = re.sub(r"//[^/@]+@", "//", v)  # never keep credentials embedded in a remote URL
            if v:
                info[key] = v
        except Exception:
            pass
    _REPO_INFO[root] = info
    return info


def actor(root):
    a = os.environ.get("GITHUB_ACTOR")
    if a:
        return "github:" + a
    try:
        e = git(["config", "user.email"], root, check=False).strip()
        if e:
            return e
    except Exception:
        pass
    return os.environ.get("USER") or "unknown"


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def last_hash_in(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = [l for l in f.read().splitlines() if l.strip()]
        return json.loads(lines[-1].decode()).get("hash") if lines else None
    except Exception:
        return None


def finding_record(f, policy):
    hashed = prefix_match(f.rule, (policy.get("evidence", {}) or {}).get("hash_paths_for_rules", []))
    path = f.path
    if path and hashed:
        path = "sha256:" + hashlib.sha256(path.encode()).hexdigest()[:16]
    rec = {"rule": f.rule, "action": f.action, "path": path, "line": f.line}
    if f.exception:
        rec["exception"] = f.exception
    return rec


def record_evidence(policy, root, event, decision, findings, extra=None):
    ev = policy.get("evidence", {}) or {}
    if not ev.get("enabled", True):
        return None
    if decision == "allow" and not findings and not ev.get("log_allowed", True):
        return None
    try:
        d = evidence_dir(policy, root)
        os.makedirs(d, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        path = os.path.join(d, now.strftime("%Y-%m") + ".jsonl")
        rec = {
            "v": 1, "ts": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "event": event, "decision": decision,
            "mode": policy.get("mode"), "covered_runtime": covered_runtime(policy),
            "findings": [finding_record(f, policy) for f in findings][:200],
            "policy": {"version": policy_version(policy), "sha256": policy.get("_policy_sha256"),
                       "default_sha256": policy.get("_default_sha256"), "schema": SCHEMA_VERSION},
            "plugin_version": PLUGIN_VERSION, "repo": repo_info(root), "actor": actor(root),
        }
        if extra:
            rec.update(extra)
        f = open(path, "a+")
        try:
            try:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except Exception:
                pass
            prev = last_hash_in(path)
            if prev is None:
                older = sorted(x for x in os.listdir(d) if x.endswith(".jsonl") and x < os.path.basename(path))
                prev = last_hash_in(os.path.join(d, older[-1])) if older else None
            rec["prev"] = prev or GENESIS
            rec["hash"] = hashlib.sha256(canon(rec).encode()).hexdigest()
            f.write(canon(rec) + "\n")
            f.flush()
        finally:
            f.close()
        return rec["hash"]
    except Exception as e:
        sys.stderr.write("hipaa-guardrails: couldn't write evidence (%s)\n" % e.__class__.__name__)
        return None


def evidence_files(d):
    if not os.path.isdir(d):
        return []
    return [os.path.join(d, x) for x in sorted(os.listdir(d)) if re.match(r"^\d{4}-\d{2}\.jsonl$", x)]


def verify_chain(d):
    problems, count, prev = [], 0, GENESIS
    for path in evidence_files(d):
        with open(path) as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                count += 1
                try:
                    rec = json.loads(line)
                except Exception:
                    problems.append("%s:%d is not valid JSON" % (os.path.basename(path), n))
                    prev = None
                    continue
                h = rec.pop("hash", None)
                if hashlib.sha256(canon(rec).encode()).hexdigest() != h:
                    problems.append("%s:%d was altered (hash doesn't match its contents)" % (os.path.basename(path), n))
                if prev is not None and rec.get("prev") != prev:
                    problems.append("%s:%d doesn't follow the record before it (a record was removed or reordered)" % (os.path.basename(path), n))
                prev = h
    return problems, count, prev


def load_records(d, since=None):
    for path in evidence_files(d):
        with open(path) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if since and rec.get("ts", "") < since:
                    continue
                yield rec


def evidence_summary(d, since=None):
    s = {"records": 0, "by_event": {}, "by_decision": {}, "by_rule": {}, "exceptions_used": {}, "policy_versions": {},
         "plugin_versions": {}, "actors": set(), "first": None, "last": None, "policy_changes": []}
    for rec in load_records(d, since):
        s["records"] += 1
        for k, key in (("by_event", "event"), ("by_decision", "decision")):
            s[k][rec.get(key)] = s[k].get(rec.get(key), 0) + 1
        pv = (rec.get("policy") or {}).get("version")
        s["policy_versions"][pv] = s["policy_versions"].get(pv, 0) + 1
        s["plugin_versions"][rec.get("plugin_version")] = s["plugin_versions"].get(rec.get("plugin_version"), 0) + 1
        s["actors"].add(rec.get("actor"))
        s["first"] = s["first"] or rec.get("ts")
        s["last"] = rec.get("ts")
        for f in rec.get("findings", []):
            r = s["by_rule"].setdefault(f.get("rule"), {"deny": 0, "ask": 0, "warn": 0, "excepted": 0})
            if f.get("exception"):
                r["excepted"] += 1
                s["exceptions_used"][f["exception"]] = s["exceptions_used"].get(f["exception"], 0) + 1
            else:
                r[f.get("action", "warn")] = r.get(f.get("action", "warn"), 0) + 1
        if rec.get("policy_change", {}).get("changed"):
            s["policy_changes"].append({"ts": rec.get("ts"), **{k: v for k, v in rec["policy_change"].items() if k != "changed"}})
    s["actors"] = sorted(a for a in s["actors"] if a)
    return s


def summary_markdown(s, problems, head, title="HIPAA guardrails evidence report"):
    L = ["# " + title, "",
         "- Records: %d (%s to %s)" % (s["records"], s["first"] or "-", s["last"] or "-"),
         "- Chain: %s" % ("intact" if not problems else "BROKEN: " + "; ".join(problems[:5])),
         "- Head hash: `%s`" % (head or "-"),
         "- Policy versions in force: %s" % ", ".join("%s (%d)" % kv for kv in s["policy_versions"].items()),
         "- Plugin versions: %s" % ", ".join("%s (%d)" % kv for kv in s["plugin_versions"].items()),
         "- People and CI identities: %d" % len(s["actors"]), "",
         "| Event | Count |", "|---|---|"]
    L += ["| %s | %d |" % kv for kv in sorted(s["by_event"].items(), key=lambda x: str(x[0]))]
    L += ["", "| Decision | Count |", "|---|---|"]
    L += ["| %s | %d |" % kv for kv in sorted(s["by_decision"].items(), key=lambda x: str(x[0]))]
    L += ["", "| Rule | Denied | Asked | Warned | Excepted |", "|---|---|---|---|---|"]
    L += ["| %s | %d | %d | %d | %d |" % (k, v.get("deny", 0), v.get("ask", 0), v.get("warn", 0), v.get("excepted", 0)) for k, v in sorted(s["by_rule"].items(), key=lambda x: str(x[0]))]
    if s["exceptions_used"]:
        L += ["", "Exceptions used: " + ", ".join("%s (%d)" % kv for kv in sorted(s["exceptions_used"].items()))]
    if s["policy_changes"]:
        L += ["", "Policy changes seen in CI:"]
        for c in s["policy_changes"]:
            L.append("- %s: %s -> %s, approver %s; %d loosening(s)" % (c.get("ts"), c.get("from"), c.get("to"), c.get("approver"), len(c.get("loosened", []))))
    L += ["", "Records hold rule ids, file paths (hashed for PHI-path rules), line numbers and decisions. They never hold file contents, prompts, commands or matched values."]
    return "\n".join(L) + "\n"


def evidence_cmd(argv, policy, root):
    sub = argv[0] if argv else "path"
    d = os.path.abspath(argv[argv.index("--dir") + 1]) if "--dir" in argv else evidence_dir(policy, root)
    since = argv[argv.index("--since") + 1] if "--since" in argv else None
    if sub == "path":
        print(d)
        return 0
    problems, count, head = verify_chain(d)
    if sub == "head":
        print(head or GENESIS)
        return 0
    if sub == "verify":
        for p in problems:
            print("BROKEN " + p)
        print("hipaa-guardrails evidence: %d record(s), chain %s, head %s" % (count, "intact" if not problems else "BROKEN", head))
        return 1 if problems else 0
    s = evidence_summary(d, since)
    if sub == "report":
        if "--format" in argv and argv[argv.index("--format") + 1] == "json":
            print(json.dumps({**s, "chain_ok": not problems, "chain_problems": problems, "head": head}, indent=2, default=list))
        else:
            sys.stdout.write(summary_markdown(s, problems, head))
        return 1 if problems else 0
    if sub == "export":
        out = os.path.abspath(argv[argv.index("--out") + 1]) if "--out" in argv else os.path.join(os.getcwd(), "hipaa-guardrails-evidence-" + today().isoformat())
        os.makedirs(out, exist_ok=True)
        import shutil
        names = []
        for p in evidence_files(d):
            shutil.copy2(p, os.path.join(out, os.path.basename(p)))
            names.append(os.path.basename(p))
        with open(os.path.join(out, "report.md"), "w") as f:
            f.write(summary_markdown(s, problems, head))
        with open(os.path.join(out, "report.json"), "w") as f:
            json.dump({**s, "chain_ok": not problems, "chain_problems": problems, "head": head}, f, indent=2, default=list)
        snap = {k: v for k, v in policy.items() if not k.startswith("_")}
        with open(os.path.join(out, "policy-merged.json"), "w") as f:
            json.dump(snap, f, indent=2)
        if os.path.exists(os.path.join(root, REPO_POLICY_NAME)):
            shutil.copy2(os.path.join(root, REPO_POLICY_NAME), os.path.join(out, "repo-policy.json"))
        names += ["report.md", "report.json", "policy-merged.json"] + (["repo-policy.json"] if os.path.exists(os.path.join(out, "repo-policy.json")) else [])
        with open(os.path.join(out, "MANIFEST.sha256"), "w") as f:
            for n in sorted(names):
                f.write("%s  %s\n" % (file_sha256(os.path.join(out, n)), n))
        print(out)
        return 1 if problems else 0
    print(__doc__)
    return 2


# ================================================================ output

def always_enforced(f, policy):
    return prefix_match(f.rule, policy.get("always_enforce", []))


def worst(findings):
    return max((SEVERITY.get(f.action, 0) for f in findings), default=0)


def hook_reason(findings, notes=()):
    lines = ["HIPAA guardrails flagged this action:"]
    for f in sorted(findings, key=lambda x: -SEVERITY.get(x.action, 0))[:12]:
        lines.append("- " + f.text())
    for n in notes:
        lines.append("- note: " + n)
    lines.append("Rules: see the hipaa-guardrails skill. Matched values are never shown.")
    return "\n".join(lines)


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")


def run_hook(kind):
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    cwd = data.get("cwd") or os.getcwd()
    root = find_repo_root(cwd)
    policy = load_policy(root)
    checker = Checker(policy, root)
    mode = policy.get("mode", "enforce")
    ctx = {"session_id": data.get("session_id"), "tool": data.get("tool_name") if kind != "userprompt" else None}

    if kind == "userprompt":
        prompt = data.get("prompt") or data.get("user_prompt") or ""
        if covered_runtime(policy):
            record_evidence(policy, root, "userprompt", "allow", [], ctx)
            return 0
        found = [f for f in checker.line_findings(None, [(None, prompt)], all_scopes=True) if f.rule.startswith("PHI-")]
        if found:
            rules = ", ".join(sorted({f.rule for f in found}))
            record_evidence(policy, root, "userprompt", "block", [Finding("PHI-EGRESS", "deny", "", None)] + [Finding(f.rule, f.action, "", None) for f in found], ctx)
            emit({"decision": "block", "reason":
                  "This prompt looks like it holds patient identifiers (%s). This session isn't BAA-covered, so the prompt was not sent. Describe the case with synthetic data instead." % rules})
        else:
            record_evidence(policy, root, "userprompt", "allow", [], ctx)
        return 0

    tool = data.get("tool_name", "")
    tin = data.get("tool_input") or {}
    findings = checker.apply_exceptions(check_tool(tool, tin, checker, policy, root, cwd))
    active = [f for f in findings if not f.exception]
    notes = checker.problems[:3]
    blocking = active if mode == "enforce" else [f for f in active if always_enforced(f, policy)]
    level = worst(blocking)
    if level <= SEVERITY["warn"]:
        decision = "warn" if active or notes else "allow"
        record_evidence(policy, root, "hook", decision, findings, ctx)
        if active or notes:
            emit({"systemMessage": hook_reason(active, notes)})
        return 0
    decision = "deny" if level >= SEVERITY["deny"] else "ask"
    record_evidence(policy, root, "hook", decision, findings, ctx)
    ordered = blocking + [f for f in active if f not in blocking]
    emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": hook_reason(ordered, notes),
    }})
    return 0


def report(findings, fmt, policy):
    fail_on = set((policy.get("ci", {}) or {}).get("fail_on", ["deny"]))
    warn_on = set((policy.get("ci", {}) or {}).get("warn_on", ["ask", "warn"]))
    failed = False
    for f in findings:
        if f.exception:
            if fmt == "github":
                loc = (" file=%s" % f.path + (",line=%s" % f.line if f.line else "")) if f.path else ""
                sys.stdout.write("::notice%s,title=HIPAA guardrails exception %s::%s covered by registered exception %s\n" % (loc, f.exception, f.rule, f.exception))
            continue
        if f.action in fail_on and (policy.get("mode", "enforce") == "enforce" or always_enforced(f, policy)):
            failed, kind = True, "error"
        elif f.action in warn_on or f.action in fail_on:
            kind = "warning"
        else:
            continue
        if fmt == "github":
            loc = (" file=%s" % f.path + (",line=%s" % f.line if f.line else "")) if f.path else ""
            sys.stdout.write("::%s%s,title=HIPAA guardrails %s::%s\n" % (kind, loc, f.rule, f.message.replace("\n", " ")))
        else:
            sys.stdout.write("%s %s\n" % (kind.upper(), f.text()))
    active = [f for f in findings if not f.exception]
    sys.stdout.write("hipaa-guardrails: %d finding(s), %d covered by exceptions%s\n" % (len(active), len(findings) - len(active), ", failing" if failed else ""))
    return 1 if failed else 0


def step_summary(findings, policy, failed, head, change):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    counts = {}
    for f in findings:
        k = (f.rule, "excepted" if f.exception else f.action)
        counts[k] = counts.get(k, 0) + 1
    L = ["## HIPAA guardrails", "",
         "Result: **%s** · policy %s · plugin %s · mode %s" % ("failed" if failed else "passed", policy_version(policy), PLUGIN_VERSION, policy.get("mode")), ""]
    if counts:
        L += ["| Rule | Outcome | Count |", "|---|---|---|"] + ["| %s | %s | %d |" % (k[0], k[1], v) for k, v in sorted(counts.items())]
    else:
        L.append("No findings.")
    if change.get("changed"):
        L += ["", "Policy changed %s -> %s (approver: %s)." % (change.get("from"), change.get("to"), change.get("approver"))]
        L += ["- loosened: " + l for l in change.get("loosened", [])]
    if head:
        L += ["", "Evidence record hash: `%s`" % head]
    with open(path, "a") as f:
        f.write("\n".join(L) + "\n")


BASELINE_NAME = ".hipaa-guardrails.baseline.json"


def baseline_key(f, text):
    return "%s|%s|%s" % (f.rule, f.path, hashlib.sha256(normalize(text or "").strip().encode()).hexdigest()[:16])


def main(argv):
    if len(argv) < 2:
        sys.stdout.write(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "version":
        sys.stdout.write("hipaa-guardrails %s (schema %d)\n" % (PLUGIN_VERSION, SCHEMA_VERSION))
        return 0
    if cmd == "hook":
        kind = argv[2] if len(argv) > 2 else "pretooluse"
        try:
            return run_hook(kind)
        except Exception as e:  # a checker bug shouldn't brick every session, unless the policy says fail closed
            try:
                pol = load_policy(find_repo_root(os.getcwd()))
                fail_closed = bool(pol.get("fail_closed"))
                record_evidence(pol, find_repo_root(os.getcwd()), "hook-error", "deny" if fail_closed else "allow", [], {"error": e.__class__.__name__})
            except Exception:
                fail_closed = False
            sys.stderr.write("hipaa-guardrails hook error: %s\n" % e.__class__.__name__)
            return 2 if fail_closed else 1

    root = find_repo_root(os.getcwd())
    policy = load_policy(root)
    fmt = "github" if "--github" in argv or os.environ.get("GITHUB_ACTIONS") == "true" else "text"

    if cmd == "explain":
        sys.stdout.write(json.dumps({k: v for k, v in policy.items() if not k.startswith("_")}, indent=2) + "\n")
        return 0
    if cmd == "validate-config":
        problems, _ = validate_config(policy, root)
        return report(problems, fmt, dict(policy, mode="enforce"))
    if cmd == "evidence":
        return evidence_cmd(argv[2:], policy, root)

    checker = Checker(policy, root)
    if cmd == "staged":
        findings = checker.apply_exceptions(staged_findings(checker, root, "--all" in argv))
        rc = report(findings, fmt, policy)
        record_evidence(policy, root, "precommit", "block" if rc else "allow", findings)
        return rc
    if cmd == "scan":
        findings, change, extra = [], {}, {}
        cfg, _ = validate_config(policy, root)
        findings += cfg
        if "--diff" in argv:
            base = argv[argv.index("--diff") + 1]
            diff = git(["diff", "-U0", "--no-color", "--no-ext-diff", "--no-renames", base + "...HEAD"], root)
            added = set(x for x in git(["diff", "--name-only", "--no-renames", "--diff-filter=A", base + "...HEAD"], root).split("\n") if x)

            def read_head(path):
                p = os.path.join(root, path)
                if not os.path.isfile(p):
                    return None
                with open(p, errors="replace") as f:
                    return f.read()
            findings += diff_findings(checker, diff, read_head, added)
            for t in git(["ls-files"], root).split("\n"):
                if t and checker.is_env(t):
                    findings.append(Finding("ENV-TRACKED", "deny", "a .env file is committed. Remove it, rotate its keys, and keep it ignored.", t))
            pc, change = policy_change_findings(root, base, policy)
            old_policy = change.pop("_old_policy", None)
            if change.get("loosened") and old_policy is not None:
                # a PR can't loosen the policy and rely on the looser policy in the same PR:
                # its code is checked against the base branch's policy; the change applies after merge
                findings = [f for f in findings if f.rule.startswith(("CONFIG-", "EXCEPTION-", "ENV-TRACKED"))]
                checker = Checker(old_policy, root)
                findings += diff_findings(checker, diff, read_head, added)
                findings.append(Finding("POLICY-BASE-USED", "warn",
                    "this PR loosens the policy, so its code was checked against the base branch's policy. The looser policy applies to later PRs once this merges.", REPO_POLICY_NAME))
            findings += pc
            extra = {"base": base, "pr": os.environ.get("GITHUB_REF"), "run": os.environ.get("GITHUB_RUN_ID"), "policy_change": change}
        files = []
        if "--all" in argv:
            files = [os.path.join(root, x) for x in git(["ls-files"], root).split("\n") if x]
        if "--files" in argv:
            for path in argv[argv.index("--files") + 1:]:
                if path.startswith("--"):
                    break
                files.append(path)
        texts = {}
        for path in files:
            rp = rel(path, root)
            if not os.path.isfile(path):
                continue
            findings += checker.data_file_findings(rp) if not checker.ignored(rp) else []
            if checker.ignored(rp):
                continue
            with open(path, errors="replace") as f:
                text = f.read()
            lines = text.splitlines()
            texts[rp] = lines
            findings += checker.check_change(rp, [(i + 1, l) for i, l in enumerate(lines)], full_text=text, changing=False)
        findings = checker.apply_exceptions(findings)
        if "--write-baseline" in argv or "--baseline" in argv:
            def line_text(f):
                ls = texts.get(f.path) or []
                return ls[f.line - 1] if f.line and 0 < f.line <= len(ls) else ""
            if "--write-baseline" in argv:
                out = argv[argv.index("--write-baseline") + 1]
                keys = sorted({baseline_key(f, line_text(f)) for f in findings if not f.exception})
                with open(out, "w") as f:
                    json.dump({"created": today().isoformat(), "plugin_version": PLUGIN_VERSION, "fingerprints": keys}, f, indent=2)
                sys.stdout.write("wrote %d fingerprint(s) to %s\n" % (len(keys), out))
            if "--baseline" in argv:
                with open(argv[argv.index("--baseline") + 1]) as f:
                    known = set(json.load(f).get("fingerprints", []))
                findings = [f for f in findings if f.exception or baseline_key(f, line_text(f)) not in known]
        rc = report(findings, fmt, policy)
        head = record_evidence(policy, root, "ci" if "--diff" in argv else "scan", "fail" if rc else "pass", findings, extra)
        step_summary(findings, policy, rc, head, change)
        return rc
    sys.stdout.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
