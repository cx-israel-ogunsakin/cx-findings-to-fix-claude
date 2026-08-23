#!/usr/bin/env python3
"""
Findings-to-Fix (ftf): pull Triage Assist CONFIRMED findings from Checkmarx One and
fetch platform-generated fixes from the Remediation Assist Agent API.

Zero dependencies (Python 3.8+ stdlib only). Same behavior as ftf.js.

Subcommands
  resolve   [--project NAME] [--branch NAME]  -> project/scan resolution as JSON
  remediate --scan-id ID [--severity ...] [--engine ...] [--out DIR] -> fixes manifest as JSON
  stage     [--manifest FILE] [--only IDX,...] -> compute patched files without touching the workspace
                                                 (Copilot proposes them as editor edits; developer keeps/undoes)
  test      [--manifest FILE]                  -> run the project's own test runner once, read-only; report pass/fail
  apply     [--manifest FILE] [--only IDX,...] -> write fixes directly (terminal use; --overwrite for drift)
  run       [resolve args] [remediate args]   -> resolve + remediate in one go

Auth: CX_APIKEY env var, or the cx CLI config (~/.checkmarx/checkmarxcli.yaml).
All output on stdout is a single JSON document; progress goes to stderr.
"""
import argparse
import base64
import concurrent.futures as cf
import io
import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

USER_AGENT = "cx-findings-to-fix/0.1"
POLL_INITIAL = 5       # seconds before the first poll (backs off to POLL_MAX)
POLL_MAX = 30
POLL_TIMEOUT = 480     # per finding; rerunning `run` resumes a killed wait at no cost
MAX_WORKERS = 8
HTTP_TIMEOUT = 60

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="[ftf] %(message)s")
log = logging.getLogger("ftf")

HOME = os.path.normpath(os.path.abspath(os.path.expanduser("~")))
CWD = os.path.normpath(os.path.abspath(os.getcwd()))


# ---------------------------------------------------------------- utilities
def die(code, msg, **extra):
    out = {"ok": False, "error": code, "message": msg}
    out.update(extra)
    print(json.dumps(out, indent=2))
    sys.exit(1)


def emit(obj):
    print(json.dumps(obj, indent=2))


def b64json(segment):
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


def contained_path(candidate, *roots):
    """Normalize `candidate` and require it to live under one of `roots`. Returns the safe absolute path."""
    dest = os.path.normpath(os.path.abspath(candidate))
    for root in roots:
        root = os.path.normpath(os.path.abspath(root))
        if os.path.commonpath([root, dest]) == root:
            return dest
    raise ValueError(f"refusing path outside allowed roots: {dest}")


def read_text(candidate, roots):
    """Read a whole text file after confining its path to `roots`."""
    with open(contained_path(candidate, *roots), mode="r", encoding="utf-8") as fh:
        return fh.read()


def write_text(candidate, roots, text):
    with open(contained_path(candidate, *roots), mode="w", encoding="utf-8") as fh:
        fh.write(text)


def write_bytes(candidate, roots, blob):
    with open(contained_path(candidate, *roots), mode="wb") as fh:
        fh.write(blob)


def write_private_text(candidate, roots, text):
    """Owner-only (0600) writes for .ftf outputs: manifests, patches, and platform copies carry tenant source code."""
    dest = contained_path(candidate, *roots)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(dest, 0o600)


def write_private_bytes(candidate, roots, blob):
    dest = contained_path(candidate, *roots)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    os.chmod(dest, 0o600)


def makedirs_private(path):
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def http_read(url, data=None, headers=None, timeout=HTTP_TIMEOUT):
    """GET/POST a URL and return (status, bytes). Raises RuntimeError on non-2xx."""
    req = urllib.request.Request(url, data=data, headers=headers or {"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read()
    if not 200 <= status < 300:
        raise RuntimeError(f"HTTP {status} from {urllib.parse.urlsplit(url).path}: {body[:200].decode(errors='replace')}")
    return status, body


# ---------------------------------------------------------------- auth
_KEY_LINE = re.compile(r"\s*(cx_apikey|apikey|cx-apikey)\s*:\s*['\"]?([A-Za-z0-9\-_\.]{40,})['\"]?\s*$", re.I)


def _find_apikey_in_cx_config():
    cfg = os.path.join(HOME, ".checkmarx", "checkmarxcli.yaml")
    if not os.path.isfile(cfg):
        return None
    for line in read_text(cfg, (HOME,)).splitlines():
        match = _KEY_LINE.match(line)
        if match:
            return match.group(2)
    return None


class CxClient:
    def __init__(self):
        apikey = os.environ.get("CX_APIKEY") or _find_apikey_in_cx_config()
        if not apikey:
            die("no_credential",
                "No Checkmarx One API key found. Set CX_APIKEY or run: cx configure set --prop-name cx_apikey --prop-value <key>")
        try:
            iss = b64json(apikey.split(".")[1])["iss"]
        except (IndexError, ValueError, KeyError) as exc:
            log.error("credential is not a Checkmarx One API key JWT: %s", exc)
            die("bad_credential", "CX_APIKEY does not look like a Checkmarx One API key (expected a JWT).")
        form = urllib.parse.urlencode({
            "grant_type": "refresh_token", "client_id": "ast-app", "refresh_token": apikey}).encode()
        try:
            _, raw = http_read(iss + "/protocol/openid-connect/token", data=form,
                               headers={"User-Agent": USER_AGENT,
                                        "Content-Type": "application/x-www-form-urlencoded"}, timeout=30)
            tok = json.loads(raw)["access_token"]
        except (RuntimeError, ValueError, KeyError) as exc:
            log.error("token exchange failed: %s", exc)
            die("auth_failed", "Token exchange failed. The API key may be revoked or expired.")
        except urllib.error.URLError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                die("tls_certificates", "This Python cannot verify HTTPS certificates (no CA bundle). Use the system or pyenv Python, "
                    "or run the Node version: node ftf.js ...", detail=str(exc)[:200])
            die("network", f"Could not reach Checkmarx One: {exc}")
        claims = b64json(tok.split(".")[1])
        self.base = os.environ.get("CX_BASE_URL") or claims.get("ast-base-url")
        if not self.base:
            die("no_base_url", "Could not determine the Checkmarx One base URL; set CX_BASE_URL.")
        self.tenant = claims.get("tenant_name") or claims.get("azp") or "?"
        self.headers = {
            "Authorization": f"Bearer {tok}",
            "Accept": "application/json; version=1.0",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }

    def call(self, method, path, body=None, timeout=HTTP_TIMEOUT):
        """Returns (status, parsed_json_or_dict). Never raises on HTTP errors; callers check status."""
        req = urllib.request.Request(self.base + path, headers=self.headers, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        except urllib.error.URLError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                die("tls_certificates", "This Python cannot verify HTTPS certificates (no CA bundle). Use the system or pyenv Python, "
                    "or run the Node version: node ftf.js ...", detail=str(exc)[:200])
            die("network", f"Could not reach Checkmarx One: {exc}")
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError as exc:
            log.error("non-JSON response (HTTP %s) from %s: %s", status, path, exc)
            parsed = {"message": raw[:300].decode(errors="replace")}
        return status, parsed

    def get(self, path):
        return self.call("GET", path)


# ---------------------------------------------------------------- git helpers
def git(*args):
    try:
        proc = subprocess.run(["git", *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("git %s failed: %s", " ".join(args), exc)
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def local_repo_guess():
    url = git("remote", "get-url", "origin")
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    root = git("rev-parse", "--show-toplevel")
    if not url:
        return {"remote_url": "", "repo": "", "parent": "", "branch": branch, "repo_root": root}
    # https://host/scm/proj/repo.git | git@host:proj/repo.git | https://github.com/org/repo
    tail = re.sub(r"\.git$", "", url.rstrip("/"))
    parts = re.split(r"[/:]", tail)
    name = parts[-1] if parts else ""
    parent = parts[-2] if len(parts) > 1 else ""
    return {"remote_url": url, "repo": name, "parent": parent, "branch": branch, "repo_root": root}


# ---------------------------------------------------------------- resolve
def _exact_project(cx, name):
    st, body = cx.get(f"/api/projects?name={urllib.parse.quote(name, safe='')}&limit=5")
    if st != 200:
        return None
    exact = [p for p in (body.get("projects") or []) if p.get("name") == name]
    return exact[0] if exact else None


UNKNOWN_BRANCH = ".unknown"
UNKNOWN_BRANCH_NOTE = ("Checkmarx One files scans that were uploaded without branch information (zip uploads, "
                       "some CI and monorepo setups) under the branch name '.unknown'. It is a normal, valid branch.")


def _latest_completed_scan(cx, project_id, branch):
    st, scans = cx.get(f"/api/scans?project-id={project_id}&branch={urllib.parse.quote(branch, safe='')}"
                       f"&statuses=Completed&limit=1&sort=-created_at")
    scan = (scans.get("scans") or [None])[0] if st == 200 else None
    if not scan:
        return None
    return {"id": scan["id"], "created_at": scan.get("createdAt"), "engines": scan.get("engines"),
            "source_origin": scan.get("sourceOrigin"), "source_type": scan.get("sourceType")}


def _branches_with_scans(cx, project_id, max_scans=200, max_branches=10):
    """Branches that have recent completed scans, newest first, from ONE paginated query over the
    project's most recent completed scans (the scans API returns the branch on each scan). This
    replaces one-call-per-branch enumeration, which on projects with hundreds of branches took minutes.
    Only called when the cheap candidates (requested branch, local branch) have no scan."""
    seen, out, offset, page = {}, [], 0, 100
    while offset < max_scans:
        st, body = cx.get(f"/api/scans?project-id={project_id}&statuses=Completed&limit={page}&offset={offset}&sort=-created_at")
        scans = (body.get("scans") or []) if st == 200 else []
        for sc in scans:
            b = sc.get("branch")
            if b is None or b in seen:
                continue
            seen[b] = True
            out.append({"branch": b,
                        "latest_scan": {"id": sc["id"], "created_at": sc.get("createdAt"), "engines": sc.get("engines"),
                                        "source_origin": sc.get("sourceOrigin"), "source_type": sc.get("sourceType")},
                        "note": UNKNOWN_BRANCH_NOTE if b == UNKNOWN_BRANCH else None})
        if len(scans) < page:
            break
        offset += page
    return out[:max_branches], len(out)


def cmd_resolve(cx, project=None, branch=None, quiet=False):
    """Resolve project and scan.

    Branch selection, in order:
      1. --branch given: use it (must have a completed scan).
      2. Exactly one branch has completed scans (the monorepo / zip-upload norm, often '.unknown'):
         use it and say so. No question.
      3. Several branches, and the local git branch is one of them: use it.
      4. Several branches, local branch not among them (or no git): ask the developer, offering the
         branches with their latest scan dates and the newest as the suggested default.
    """
    guess = local_repo_guess()
    result = {"ok": True, "local": guess, "tenant": cx.tenant, "base_url": cx.base}

    tried, proj = [], None
    names = [project] if project else [
        f"{guess['parent']}/{guess['repo']}" if guess["parent"] and guess["repo"] else None,
        guess["repo"] or None]
    for cand in [n for n in names if n]:
        tried.append(cand)
        proj = _exact_project(cx, cand)
        if proj:
            break

    if not proj:
        needle = project or guess["repo"] or ""
        near = []
        if needle:
            st, body = cx.get(f"/api/projects?name-regex={urllib.parse.quote(needle, safe='')}&limit=10")
            if st == 200:
                near = [{"name": p["name"], "id": p["id"]} for p in (body.get("projects") or [])]
        result.update({"resolved": False, "reason": "project_not_found", "tried": tried, "candidates": near,
                       "next": "Ask the developer for the exact Checkmarx One project name (pick from candidates if listed) and rerun with --project."})
        if not quiet:
            emit(result)
        return result

    result["project"] = {"name": proj["name"], "id": proj["id"]}

    def pick(name, how):
        scan = _latest_completed_scan(cx, proj["id"], name)
        if scan:
            return {"branch": name, "latest_scan": scan, "note": UNKNOWN_BRANCH_NOTE if name == UNKNOWN_BRANCH else None}, how
        return None, None

    # 1. Cheap candidates first: one call each. This is the path almost every git-based developer takes.
    chosen, how = (None, None)
    if branch:
        chosen, how = pick(branch, "requested")
        if not chosen:
            with_scans, n_total = _branches_with_scans(cx, proj["id"])
            result.update({"resolved": False, "reason": "no_completed_scan_on_branch", "branch": branch,
                           "branches_with_scans": with_scans, "branches_total": n_total,
                           "next": "The requested branch has no completed scan. Show branches_with_scans (branch, latest scan date) as a numbered list, mention they can type another branch name, and ask which to use; rerun with --branch."})
            if not quiet:
                emit(result)
            return result
    elif guess["branch"] and guess["branch"] != "HEAD":
        chosen, how = pick(guess["branch"], "matches_local_branch")

    # 2. Only on a miss: one query for the branches with recent scans.
    if not chosen:
        with_scans, n_total = _branches_with_scans(cx, proj["id"])
        result.update({"branches_with_scans": with_scans, "branches_total": n_total})
        if not with_scans:
            result.update({"resolved": False, "reason": "no_completed_scans",
                           "next": "This project has no completed scans yet. Tell the developer; nothing to fix until a scan completes."})
            if not quiet:
                emit(result)
            return result
        if n_total == 1:
            chosen, how = with_scans[0], "only_branch_with_scans"
        else:
            result.update({"resolved": False, "reason": "branch_choice_needed",
                           "local_branch": guess["branch"] or None,
                           "suggested": with_scans[0]["branch"],
                           "next": ("The local branch has no completed scan but other branches do. Show branches_with_scans "
                                    "(the most recently scanned, up to 10) as a numbered list with each latest scan date, mark "
                                    "'suggested' (the most recent) as the default, say they can also type any other branch name, "
                                    "and ask which to use; rerun with --branch.")})
            if not quiet:
                emit(result)
            return result

    result.update({"resolved": True, "branch": chosen["branch"], "branch_selected_by": how,
                   "branch_note": chosen.get("note"), "scan": chosen["latest_scan"]})
    if not quiet:
        emit(result)
    return result


# ---------------------------------------------------------------- findings + remediation
def list_confirmed(cx, scan_id, severities, engines):
    findings, offset, page = [], 0, 100
    while True:
        qs = [("scan-id", scan_id), ("limit", str(page)), ("offset", str(offset)), ("state", "CONFIRMED")]
        qs += [("severity", s) for s in severities]
        st, body = cx.get("/api/results/?" + urllib.parse.urlencode(qs))
        if st != 200:
            die("results_failed", f"/api/results returned HTTP {st}: {body.get('message')}")
        batch = body.get("results") or []
        for r in batch:
            eng = (r.get("type") or "").lower()
            if engines and eng not in engines:
                continue
            d = r.get("data") or {}
            node = (d.get("nodes") or [{}])[0]
            vd = r.get("vulnerabilityDetails") or {}
            findings.append({
                "alternate_id": r.get("alternateId") or r.get("id"),
                "display_id": r.get("id"),
                "similarity_id": r.get("similarityId"),
                "engine": eng,
                "severity": r.get("severity"),
                "state": r.get("state"),
                "status": r.get("status"),
                "query": d.get("queryName") or vd.get("cveName") or "",
                "file": node.get("fileName") or "",
                "line": node.get("line"),
                "package": d.get("packageIdentifier"),
                "recommended_version": d.get("recommendedVersion"),
                "cwe": vd.get("cweId"),
            })
        total = body.get("totalCount") or 0
        offset += len(batch)
        if not batch or offset >= total:
            break
    return findings


# ---------------------------------------------------------------- scope (monorepos)
def _norm_rel(path):
    return (path or "").replace("\\", "/").lstrip("/")


def infer_path_strip(findings, repo_root):
    """Scanner paths are relative to wherever the scan ran. Find the number of leading path components
    to strip so that most SAST finding paths resolve under repo_root. Returns (strip_count, hit_ratio)."""
    files = [_norm_rel(f["file"]) for f in findings if f.get("file")]
    if not files or not repo_root:
        return 0, 0.0
    best = (0, 0.0)
    for strip in range(0, 4):
        hits = 0
        for fp in files:
            parts = fp.split("/")
            if len(parts) <= strip:
                continue
            if os.path.isfile(os.path.join(repo_root, *parts[strip:])):
                hits += 1
        ratio = hits / len(files)
        if ratio > best[1]:
            best = (strip, ratio)
        if ratio >= 0.9:
            break
    return best


def infer_scope_subpath(repo_root):
    """If the folder the developer has open (CWD) is a subfolder of the git repo, that subfolder
    (relative, forward slashes) is the natural monorepo scope. Empty string means the whole repo."""
    try:
        rr = os.path.normpath(os.path.abspath(repo_root)); cwd = os.path.normpath(os.path.abspath(os.getcwd()))
        if os.path.commonpath([rr, cwd]) != rr or rr == cwd:
            return ""
        return os.path.relpath(cwd, rr).replace(os.sep, "/")
    except ValueError:
        return ""


def apply_scope(findings, repo_root, scope):
    """scope: 'auto' (infer from open folder), 'all', or an explicit repo-relative subpath.
    Returns (kept, info). SCA findings carry no file path and are never scoped out."""
    strip, ratio = infer_path_strip(findings, repo_root)
    sub = "" if scope in (None, "auto") else ("" if scope == "all" else _norm_rel(scope).rstrip("/"))
    if scope in (None, "auto"):
        sub = infer_scope_subpath(repo_root)
    info = {"mode": scope or "auto", "subpath": sub, "path_strip": strip, "path_match_ratio": round(ratio, 2),
            "findings_total": len(findings)}
    if not sub:
        info.update({"findings_in_scope": len(findings), "applied": False})
        return findings, info
    kept = []
    for f in findings:
        if not f.get("file"):           # SCA: package-level, no path
            kept.append(f); continue
        parts = _norm_rel(f["file"]).split("/")[strip:]
        rel = "/".join(parts)
        if rel == sub or rel.startswith(sub + "/"):
            kept.append(f)
    why = "the folder you have open" if scope in (None, "auto") else "the scope you asked for"
    info.update({"findings_in_scope": len(kept), "applied": True,
                 "note": (f"Showing findings under '{sub}' ({why}). The project has "
                          f"{len(findings)} in total; use --scope all to see everything.")})
    return kept, info


def has_existing_fix(cx, scan_id, f):
    """True when Remediation Assist has already generated a fix for this finding.
    HTTP 200 with a data payload means it exists (free to fetch); 404 means generating it
    would consume Checkmarx Credits."""
    st, body = cx.get(f"/api/remediation/remediation-details/{scan_id}/{urllib.parse.quote(f['alternate_id'], safe='')}")
    if st != 200 or not isinstance(body, dict):
        return False
    res = (body.get("results") or [{}])[0]
    data = res.get("data")
    # A payload whose data carries an error is a FAILED generation, not a usable fix;
    # counting it as existing would block regeneration forever.
    return bool(data) and not (isinstance(data, dict) and data.get("error"))


def preflight(cx, scan_id, findings):
    """Split findings into those that already have a fix and those that would need one
    generated. Runs in parallel; one cheap GET per finding."""
    have = set()
    if not findings:
        return have
    with cf.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(findings))) as ex:
        futs = {ex.submit(has_existing_fix, cx, scan_id, f): f for f in findings}
        for fut in cf.as_completed(futs):
            if fut.result():
                have.add(futs[fut]["alternate_id"])
    return have


def initiate(cx, scan_id, findings):
    buckets = {}
    for f in findings:
        buckets.setdefault(f["engine"], []).append(f["alternate_id"])
    payload = {"scanID": scan_id,
               "buckets": [{"scannerType": eng, "resultIDs": ids} for eng, ids in buckets.items() if eng in ("sast", "sca")]}
    if not payload["buckets"]:
        return {"submitted": 0}
    st, body = cx.call("POST", "/api/remediation/remediate", payload)
    if st != 202:
        die("remediate_failed", f"POST /api/remediation/remediate returned HTTP {st}: {body.get('message') or body}",
            hint="HTTP 402/403 usually means Remediation Assist is not enabled or licensed for this tenant.")
    return {"submitted": sum(len(b["resultIDs"]) for b in payload["buckets"]),
            "job_id": body.get("remediationJobId"), "published": body.get("published"),
            "existing_state": body.get("existingState")}


def poll_one(cx, scan_id, f):
    path = f"/api/remediation/remediation-details/{scan_id}/{urllib.parse.quote(f['alternate_id'], safe='')}"
    t0, delay = time.time(), POLL_INITIAL
    while True:
        st, body = cx.get(path)
        res = (body.get("results") or [{}])[0] if isinstance(body, dict) else {}
        elapsed = int(time.time() - t0)
        if st == 200 and res.get("data"):
            data = res["data"]
            return {**f, "status": "READY" if not data.get("error") else "FAILED",
                    "error": data.get("error"),
                    "summary": data.get("summary"), "analysis": data.get("analysis") or {},
                    "pr_title": data.get("pr_title"),
                    "file_changes": [{"file_path": c.get("file_path"), "diff": c.get("diff"), "note": c.get("analysis")}
                                     for c in (data.get("file_changes") or [])],
                    "tests": [{"file_path": t.get("file_path"), "framework": t.get("framework_used")}
                              for t in ((data.get("test_creation") or {}).get("test_files") or [])],
                    "zip_url": (res.get("autoPr") or {}).get("file_url"),
                    "elapsed_s": elapsed}
        if res.get("jobStatus") == "FAILED":
            return {**f, "status": "FAILED", "error": "remediation job failed", "elapsed_s": elapsed}
        if st not in (200, 404):   # 404 = job not registered yet, keep polling
            return {**f, "status": "FAILED", "error": f"HTTP {st}: {body.get('message')}", "elapsed_s": elapsed}
        if elapsed > POLL_TIMEOUT:
            return {**f, "status": "TIMEOUT", "error": f"no result after {POLL_TIMEOUT}s", "elapsed_s": elapsed}
        time.sleep(delay)
        delay = min(POLL_MAX, delay + 5)


def cmd_remediate(cx, scan_id, severities, engines, out_dir, quiet=False, meta=None, scope="auto", generate=False):
    log.info("listing CONFIRMED findings for scan %s… (severity=%s; engines=%s)",
             scan_id[:8], ",".join(severities), ",".join(engines) or "all")
    findings = list_confirmed(cx, scan_id, severities, engines)
    log.info("%d confirmed finding(s)", len(findings))
    repo_root = git("rev-parse", "--show-toplevel") or CWD
    findings, scope_info = apply_scope(findings, repo_root, scope)
    if scope_info.get("applied"):
        log.info("scope '%s': %d of %d finding(s)", scope_info["subpath"], scope_info["findings_in_scope"], scope_info["findings_total"])
    manifest = {"ok": True, "scan_id": scan_id, "tenant": cx.tenant, "base_url": cx.base,
                "repo_root": repo_root, "scope": scope_info,
                "filters": {"state": ["CONFIRMED"], "severity": severities, "engines": engines},
                "findings_total": len(findings), "results": []}
    if meta:
        manifest.update(meta)
    if not findings:
        manifest["message"] = "No CONFIRMED findings match the filters. Nothing to fix."
        _write_manifest(manifest, out_dir, quiet)
        return manifest

    have = preflight(cx, scan_id, findings)
    need = [f for f in findings if f["alternate_id"] not in have]
    manifest["credits"] = {
        "findings_total": len(findings),
        "fixes_already_generated": len(findings) - len(need),
        "fixes_to_generate": len(need),
        "note": ("Remediation Assist generates a fix for any finding that does not already have one, "
                 "which consumes Checkmarx Credits. Fixes that already exist are fetched at no cost."),
    }
    log.info("credits: %d of %d finding(s) already have a fix; %d would need generating",
             len(findings) - len(need), len(findings), len(need))

    if need and not generate:
        # Never spend Checkmarx Credits without an explicit yes. Return what already exists,
        # report the rest, and let the agent ask.
        manifest["credits"]["consent_required"] = True
        manifest["submission"] = {"submitted": 0, "reason": "consent_required"}
        manifest["next"] = (f"{len(need)} of {len(findings)} finding(s) have no fix yet. Generating them runs "
                            "Checkmarx Remediation Assist and consumes Checkmarx Credits. Tell the developer the "
                            "counts, ask whether to generate them, and on a yes rerun the same command with "
                            "--generate. Fixes that already exist are included below and cost nothing.")
        for f in need:
            manifest["results"].append({**f, "status": "NOT_GENERATED",
                                        "note": "No fix exists yet; generating one consumes Checkmarx Credits."})
        log.info("stopping before generating: rerun with --generate to spend credits on %d fix(es)", len(need))
        findings = [f for f in findings if f["alternate_id"] in have]
    elif need:
        sub = initiate(cx, scan_id, need)
        manifest["submission"] = sub
        manifest["credits"]["credits_consumed_for"] = len(need)
        log.info("generating %d fix(es) (consumes Checkmarx Credits): %s", len(need), sub)
    else:
        manifest["submission"] = {"submitted": 0, "note": "every finding already had a fix; nothing was generated"}
        log.info("every finding already had a fix; nothing generated, no credits consumed")

    if findings:
        log.info("fetching %d fix(es) in parallel (up to %d workers)…", len(findings), MAX_WORKERS)
        with cf.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(findings))) as ex:
            futs = {ex.submit(poll_one, cx, scan_id, f): f for f in findings}
            for fut in cf.as_completed(futs):
                r = fut.result()
                log.info("  %-8s %-4s %-32s -> %s (%ss)", r["severity"], r["engine"], r["query"][:32], r["status"], r.get("elapsed_s", 0))
                manifest["results"].append(r)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    manifest["results"].sort(key=lambda r: (order.get(r["severity"], 9), r["query"]))
    manifest["ready"] = sum(1 for r in manifest["results"] if r["status"] == "READY")
    manifest["failed"] = sum(1 for r in manifest["results"] if r["status"] != "READY")
    _write_manifest(manifest, out_dir, quiet)
    return manifest


def _save_platform_files(r, index, out_dir):
    """Download the platform's fully patched files while the signed zip URL is still fresh (it is
    minted once per job and expires after about an hour). Stored under .ftf/platform/<index>/ as
    reference copies for the agent; never written into the repo automatically."""
    zip_url = r.get("zip_url")
    if not zip_url:
        return
    try:
        _, blob = http_read(zip_url)
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            base = os.path.join(out_dir, "platform", f"{index:02d}")
            for name in z.namelist():
                if name.endswith("/"):
                    continue
                dest = contained_path(os.path.join(base, name), out_dir)
                makedirs_private(os.path.dirname(dest))
                write_private_bytes(dest, (out_dir,), z.read(name))
            r["platform_files_dir"] = base
            for c in r.get("file_changes", []):
                if c.get("file_path") in z.namelist():
                    c["platform_file"] = os.path.join(base, c["file_path"])
    except (RuntimeError, ValueError, OSError, zipfile.BadZipFile) as exc:
        log.error("could not save platform files for result %d: %s", index, exc)
        r["platform_files_error"] = str(exc)[:200]


def _write_manifest(manifest, out_dir, quiet):
    if out_dir:
        out_dir = contained_path(out_dir, CWD, HOME)
        makedirs_private(out_dir)
        for i, r in enumerate(manifest.get("results", [])):
            if r.get("status") != "READY":
                continue
            for j, c in enumerate(r.get("file_changes", [])):
                if c.get("diff"):
                    fname = f"{i:02d}-{j}-{os.path.basename(c['file_path'] or 'change')}.patch"
                    patch_path = os.path.join(out_dir, fname)
                    write_private_text(patch_path, (out_dir,), c["diff"] if c["diff"].endswith("\n") else c["diff"] + "\n")
                    c["patch_path"] = patch_path
            _save_platform_files(r, i, out_dir)
        manifest_path = os.path.join(out_dir, "ftf-manifest.json")
        manifest["manifest_path"] = manifest_path
        write_private_text(manifest_path, (out_dir,), json.dumps(manifest, indent=2))
    if not quiet:
        emit(manifest)


# ---------------------------------------------------------------- apply
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified_diff(original, diff):
    """Apply a single-file unified diff to `original` (str). Strict: every context/removed line must
    match exactly at the stated position (with a small drift search). Returns new text or None."""
    lines = original.splitlines(keepends=True)
    out, cursor = [], 0
    hunks, cur = [], None
    for raw in diff.splitlines(keepends=True):
        if raw.startswith(("diff --git", "index ", "--- ", "+++ ")):
            continue
        m = _HUNK.match(raw)
        if m:
            cur = {"old_start": int(m.group(1)), "lines": []}
            hunks.append(cur)
            continue
        if cur is not None and raw[:1] in (" ", "-", "+", "\\"):
            cur["lines"].append(raw)
    for h in hunks:
        old_block = [l[1:] for l in h["lines"] if l[0] in (" ", "-")]
        new_block = [l[1:] for l in h["lines"] if l[0] in (" ", "+")]
        # find old_block at or near old_start (1-based); allow small drift either way
        want = h["old_start"] - 1
        pos = None
        for delta in [0] + [d for k in range(1, 50) for d in (k, -k)]:
            i = want + delta
            if i < cursor or i < 0 or i + len(old_block) > len(lines):
                continue
            if [l.rstrip("\r\n") for l in lines[i:i + len(old_block)]] == [l.rstrip("\r\n") for l in old_block]:
                pos = i
                break
        if pos is None:
            return None
        out.extend(lines[cursor:pos])
        out.extend(new_block)
        cursor = pos + len(old_block)
    out.extend(lines[cursor:])
    return "".join(out)


def _apply_without_git(diff, file_path, repo_root):
    """Fallback for folders that are not git repositories (e.g. a zip export)."""
    dest = contained_path(os.path.join(repo_root, file_path), repo_root)
    original = read_text(dest, (repo_root,)) if os.path.isfile(dest) else ""
    patched = apply_unified_diff(original, diff)
    if patched is None:
        return False
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    write_text(dest, (repo_root,), patched)
    return True


def _overwrite_from_platform(c, repo_root):
    """Explicit opt-in only: copy the platform's fully patched file over the local one."""
    src = c.get("platform_file")
    if not src or not os.path.isfile(src):
        return False
    dest = contained_path(os.path.join(repo_root, c["file_path"]), repo_root)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(src, mode="rb") as fh:
        write_bytes(dest, (repo_root,), fh.read())
    return True


def _is_git_tree(root):
    proc = subprocess.run(["git", "-C", root, "rev-parse", "--is-inside-work-tree"],
                          capture_output=True, text=True, check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def _resolve_repo_root(explicit, manifest):
    """Returns (root, is_git). Prefer --repo-root, then the root recorded by `run`, then the current git
    tree, then the folder holding the manifest's parent (.ftf/..), then cwd. A plain folder (zip export,
    no .git) is accepted; fixes are then applied without git."""
    manifest_dir_parent = os.path.dirname(os.path.dirname(manifest.get("manifest_path") or "")) or None
    for cand in (explicit, manifest.get("repo_root"), git("rev-parse", "--show-toplevel"), manifest_dir_parent, CWD):
        if cand and os.path.isdir(cand):
            root = os.path.normpath(os.path.abspath(cand))
            return root, _is_git_tree(root)
    die("no_target_folder", "Could not find the folder to apply fixes into. Run `apply` from the project root, or pass --repo-root.")


def _load_manifest_for_apply(manifest_path, repo_root):
    manifest_path = os.path.normpath(os.path.abspath(manifest_path))
    if not os.path.isfile(manifest_path):
        for base in (repo_root, git("rev-parse", "--show-toplevel")):
            if base and os.path.isfile(os.path.join(base, ".ftf", "ftf-manifest.json")):
                manifest_path = os.path.normpath(os.path.join(base, ".ftf", "ftf-manifest.json"))
                break
    if not os.path.isfile(manifest_path):
        die("no_manifest", f"Manifest not found at {manifest_path}. Run `run` first, or pass --manifest.")
    return json.loads(read_text(manifest_path, (os.path.dirname(manifest_path),)))


def cmd_stage(manifest_path, only=None, repo_root=None):
    """Compute every fix against the CURRENT local files without writing anything.
    For each file change: if the exact diff fits the local file, emit the full patched content
    (`ready`, with `patched_path` holding a copy under .ftf/staged/) so the agent can propose it as an
    editor edit the developer accepts or rejects per file. If it does not fit, emit `needs_assist` with the
    patch and analysis so the agent places the change by hand. The workspace is never modified here."""
    manifest = _load_manifest_for_apply(manifest_path, repo_root)
    repo_root, is_git = _resolve_repo_root(repo_root, manifest)
    out_dir = os.path.dirname(manifest.get("manifest_path") or os.path.join(repo_root, ".ftf"))
    staged_dir = os.path.join(out_dir, "staged")
    report = {"ok": True, "repo_root": repo_root, "git_repo": is_git, "ready": [], "needs_assist": [], "failed": [], "skipped": []}
    for i, r in enumerate(manifest.get("results", [])):
        if only is not None and i not in only:
            report["skipped"].append({"index": i, "query": r.get("query")})
            continue
        if r.get("status") != "READY":
            report["skipped"].append({"index": i, "query": r.get("query"), "reason": r.get("status")})
            continue
        for j, c in enumerate(r.get("file_changes", [])):
            file_path = c.get("file_path")
            entry = {"index": i, "query": r.get("query"), "severity": r.get("severity"), "file": file_path,
                     "summary": r.get("summary"), "patch_path": c.get("patch_path")}
            diff = c.get("diff") or ""
            if not diff.strip() or not file_path:
                entry["reason"] = "empty diff"
                report["failed"].append(entry)
                continue
            try:
                dest = contained_path(os.path.join(repo_root, file_path), repo_root)
                original = read_text(dest, (repo_root,)) if os.path.isfile(dest) else ""
                patched = apply_unified_diff(original, diff)
            except (ValueError, OSError) as exc:
                entry["reason"] = f"could not read local file: {exc}"[:300]
                report["failed"].append(entry)
                continue
            if patched is None:
                entry.update({
                    "status": "NEEDS_ASSIST",
                    "reason": "local file differs from the scanned version; exact diff does not fit",
                    "platform_file": c.get("platform_file"),
                    "analysis": r.get("analysis"),
                    "hint": ("Read patch_path (the intended change) and the local file, then propose the same change "
                             "in the current code as an editor edit, preserving surrounding local edits."),
                })
                report["needs_assist"].append(entry)
                continue
            makedirs_private(staged_dir)
            staged = os.path.join(staged_dir, f"{i:02d}-{j}-{os.path.basename(file_path)}")
            write_private_text(staged, (out_dir,), patched)
            entry.update({"status": "READY", "exists": os.path.isfile(dest), "patched_path": staged,
                          "lines_added": sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")),
                          "lines_removed": sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")),
                          "hint": ("Propose an editor edit that replaces the full content of `file` with the content of "
                                   "`patched_path` (or apply the diff at `patch_path`). The developer accepts or rejects it "
                                   "in the editor. Do not write the file yourself with a terminal command.")})
            report["ready"].append(entry)
    report["tests"] = sorted({t.get("file_path") for r in manifest.get("results", []) for t in (r.get("tests") or []) if t.get("file_path")})
    emit(report)
    return report


def cmd_apply(manifest_path, only=None, repo_root=None, overwrite=False):
    """Tiered apply.
    Tier 1: exact diff (git apply --3way in a repo; strict built-in applier in a plain folder).
    If that fails the file has drifted from the scanned version. The script does NOT guess: it reports
    the entry as NEEDS_ASSIST with the patch, the platform's reference copy, and the analysis, so the
    agent (Copilot) can place the same change into the current code by hand while preserving local edits.
    --overwrite: explicit opt-in to copy the platform's full patched file over drifted files instead.
    Intended for terminal use; the Copilot agent uses `stage` so the developer accepts edits in the editor."""
    manifest = _load_manifest_for_apply(manifest_path, repo_root)
    repo_root, is_git = _resolve_repo_root(repo_root, manifest)
    report = {"ok": True, "repo_root": repo_root, "git_repo": is_git,
              "applied": [], "needs_assist": [], "failed": [], "skipped": []}
    if not is_git:
        report["note"] = ("Target folder is not a git repository; fixes are written directly to files "
                          "(nothing is staged). Review with the editor's diff view.")
    for i, r in enumerate(manifest.get("results", [])):
        if only is not None and i not in only:
            report["skipped"].append({"index": i, "query": r.get("query")})
            continue
        if r.get("status") != "READY":
            report["skipped"].append({"index": i, "query": r.get("query"), "reason": r.get("status")})
            continue
        for c in r.get("file_changes", []):
            file_path = c.get("file_path")
            entry = {"index": i, "query": r.get("query"), "file": file_path}
            diff = c.get("diff") or ""
            if not diff.strip() or not file_path:
                entry["reason"] = "empty diff"
                report["failed"].append(entry)
                continue
            # ---- tier 1: exact diff
            reason = ""
            if is_git:
                proc = subprocess.run(["git", "apply", "--3way", "--whitespace=nowarn", "-"],
                                      cwd=repo_root, input=diff if diff.endswith("\n") else diff + "\n",
                                      capture_output=True, text=True, check=False)
                if proc.returncode == 0:
                    entry["method"] = "git apply --3way"
                    report["applied"].append(entry)
                    continue
                reason = (proc.stderr or proc.stdout).strip()[:300]
            else:
                try:
                    if _apply_without_git(diff, file_path, repo_root):
                        entry["method"] = "unified diff applied directly (folder is not a git repo)"
                        report["applied"].append(entry)
                        continue
                    reason = "diff context did not match the local file"
                except (ValueError, OSError) as exc:
                    reason = f"direct apply failed: {exc}"[:300]
            # ---- explicit overwrite (opt-in)
            if overwrite:
                try:
                    if _overwrite_from_platform(c, repo_root):
                        entry["method"] = "OVERWRITTEN with the platform's full patched file (local edits to this file were discarded; review carefully)"
                        report["applied"].append(entry)
                        continue
                except (ValueError, OSError) as exc:
                    reason += f"; overwrite failed: {exc}"
            # ---- hand off to the agent
            entry.update({
                "status": "NEEDS_ASSIST",
                "reason": reason,
                "patch_path": c.get("patch_path"),
                "platform_file": c.get("platform_file"),
                "summary": r.get("summary"),
                "analysis": r.get("analysis"),
                "hint": ("The local file differs from the scanned version, so the exact diff did not apply. "
                         "Read patch_path (the intended change) and the local file, then make the same change "
                         "in the current code with an editor edit, preserving surrounding local edits. "
                         "platform_file is the platform's fully patched reference copy of the scanned version."),
            })
            report["needs_assist"].append(entry)
    emit(report)
    return report


# ---------------------------------------------------------------- test runner
TEST_TIMEOUT = 300


def detect_test_runner(repo_root):
    """Find the project's OWN test runner. Returns (argv, label) or (None, reason).
    Never installs anything, never writes anything. On Windows npm/mvn/gradle are
    .cmd/.bat launchers, which need their real names to spawn without a shell."""
    win = os.name == "nt"
    pj = os.path.join(repo_root, "package.json")
    if os.path.isfile(pj):
        try:
            d = json.loads(read_text(pj, (repo_root,)))
        except (ValueError, OSError):
            d = {}
        script = ((d.get("scripts") or {}).get("test") or "").strip()
        if not script or script.lower().startswith("echo ") or "no test specified" in script.lower() or script.lower() == "cx test":
            return None, f"package.json has no usable test script (scripts.test is {script!r})"
        if not os.path.isdir(os.path.join(repo_root, "node_modules")):
            return None, "node_modules is not installed; run the project's install step (e.g. npm install) first"
        return ["npm.cmd" if win else "npm", "test", "--silent"], f"npm test ({script})"
    if any(os.path.isfile(os.path.join(repo_root, f)) for f in ("pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini")) \
            or os.path.isdir(os.path.join(repo_root, "tests")) or os.path.isdir(os.path.join(repo_root, "test")):
        probe = subprocess.run([sys.executable, "-m", "pytest", "--version"], capture_output=True, text=True, check=False)
        if probe.returncode == 0:
            return [sys.executable, "-m", "pytest", "-q"], "python -m pytest"
        return None, "pytest is not installed in this Python environment"
    if os.path.isfile(os.path.join(repo_root, "pom.xml")):
        return ["mvn.cmd" if win else "mvn", "-q", "test"], "mvn test"
    if os.path.isfile(os.path.join(repo_root, "build.gradle")) or os.path.isfile(os.path.join(repo_root, "build.gradle.kts")):
        wrapper = os.path.join(repo_root, "gradlew.bat" if win else "gradlew")
        return [wrapper, "test"] if os.path.isfile(wrapper) else (["gradle.bat" if win else "gradle", "test"]), "gradle test"
    if os.path.isfile(os.path.join(repo_root, "go.mod")):
        return ["go", "test", "./..."], "go test ./..."
    # one level down (monorepo-shaped projects keep the runner in a service folder)
    try:
        subs = sorted(d for d in os.listdir(repo_root) if os.path.isdir(os.path.join(repo_root, d)) and not d.startswith("."))
    except OSError:
        subs = []
    hints = [d for d in subs if os.path.isfile(os.path.join(repo_root, d, "package.json")) or os.path.isdir(os.path.join(repo_root, d, "tests"))]
    if hints:
        return None, (f"no test runner at the project root; found test setups under {', '.join(hints[:4])}. "
                      f"Open that folder (or rerun with --repo-root) to run its tests")
    return None, "no recognised test runner (package.json scripts.test, pytest, maven, gradle, go)"


def cmd_test(manifest_path, repo_root=None, only_files=None):
    """Run the project's own test runner once, read-only, and report. The agent relays the result.
    If the runner is not set up, say so; this command never installs, edits, or creates anything."""
    manifest = _load_manifest_for_apply(manifest_path, repo_root)
    repo_root, _ = _resolve_repo_root(repo_root, manifest)
    platform_tests = sorted({t.get("file_path") for r in manifest.get("results", []) for t in (r.get("tests") or []) if t.get("file_path")})
    present = [t for t in platform_tests if os.path.isfile(os.path.join(repo_root, t))]
    argv, label = detect_test_runner(repo_root)
    report = {"ok": True, "repo_root": repo_root, "platform_tests": platform_tests, "platform_tests_present": present}
    if not argv:
        report.update({"ran": False, "reason": label,
                       "note": "The project's test runner is not set up, so the tests were not run. Tell the developer exactly this "
                               "and stop; do not install dependencies, edit package files, or create another runner."})
        emit(report)
        return report
    if only_files and argv[0] == sys.executable:      # pytest accepts file args; npm/mvn/gradle/go do not
        argv = argv + [f for f in only_files if os.path.isfile(os.path.join(repo_root, f))]
    try:
        proc = subprocess.run(argv, cwd=repo_root, capture_output=True, text=True, timeout=TEST_TIMEOUT, check=False)
        out = (proc.stdout or "") + (proc.stderr or "")
        report.update({"ran": True, "runner": label, "exit_code": proc.returncode, "passed": proc.returncode == 0,
                       "output_tail": out[-3000:]})
    except subprocess.TimeoutExpired:
        report.update({"ran": True, "runner": label, "passed": False, "reason": f"timed out after {TEST_TIMEOUT}s"})
    except (OSError, subprocess.SubprocessError) as exc:
        report.update({"ran": False, "runner": label, "reason": f"could not start the runner: {exc}"})
    emit(report)
    return report


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(prog="ftf", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_resolve_args(p):
        p.add_argument("--project", help="Checkmarx One project name (exact). Default: guessed from git remote.")
        p.add_argument("--branch", help="Branch with a completed scan. Default: current git branch.")

    def add_remediate_args(p, need_scan=True):
        if need_scan:
            p.add_argument("--scan-id", required=True)
        p.add_argument("--severity", nargs="+", default=["CRITICAL", "HIGH"])
        p.add_argument("--engine", nargs="+", default=["sast"], help="sast and/or sca (default: sast)")
        p.add_argument("--out", default=".ftf", help="Directory for manifest and .patch files (default: .ftf)")
        p.add_argument("--generate", action="store_true",
                       help="Allow Remediation Assist to generate fixes for findings that do not have one yet. This consumes Checkmarx Credits. Without it the tool fetches only fixes that already exist and reports what generating would cost.")
        p.add_argument("--scope", default="auto",
                       help="Monorepos: 'auto' keeps findings under the folder you have open (default), 'all' keeps every finding, or give a repo-relative subpath")

    add_resolve_args(sub.add_parser("resolve"))
    add_remediate_args(sub.add_parser("remediate"))
    p_run = sub.add_parser("run")
    add_resolve_args(p_run)
    add_remediate_args(p_run, need_scan=False)
    p_stage = sub.add_parser("stage")
    p_stage.add_argument("--manifest", default=".ftf/ftf-manifest.json")
    p_stage.add_argument("--only", help="Comma-separated result indexes to stage (default: all READY)")
    p_stage.add_argument("--repo-root")
    p_test = sub.add_parser("test")
    p_test.add_argument("--manifest", default=".ftf/ftf-manifest.json")
    p_test.add_argument("--repo-root")
    p_test.add_argument("--only", nargs="*", help="Limit to these test files where the runner supports it (pytest)")
    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--manifest", default=".ftf/ftf-manifest.json")
    p_apply.add_argument("--only", help="Comma-separated result indexes to apply (default: all READY)")
    p_apply.add_argument("--repo-root")
    p_apply.add_argument("--overwrite", action="store_true",
                         help="For drifted files, copy the platform's full patched file over the local one instead of handing off (discards local edits to that file)")

    a = ap.parse_args()
    if a.cmd == "test":
        cmd_test(a.manifest, a.repo_root, a.only)
        return
    if a.cmd == "stage":
        only = [int(x) for x in a.only.split(",")] if a.only else None
        cmd_stage(a.manifest, only, a.repo_root)
        return
    if a.cmd == "apply":
        only = [int(x) for x in a.only.split(",")] if a.only else None
        cmd_apply(a.manifest, only, a.repo_root, overwrite=a.overwrite)
        return

    cx = CxClient()
    engines = [e.lower() for e in a.engine] if hasattr(a, "engine") else ["sast"]
    if a.cmd == "resolve":
        cmd_resolve(cx, a.project, a.branch)
    elif a.cmd == "remediate":
        cmd_remediate(cx, a.scan_id, [s.upper() for s in a.severity], engines, a.out, scope=a.scope, generate=a.generate)
    elif a.cmd == "run":
        res = cmd_resolve(cx, a.project, a.branch, quiet=True)
        if not res.get("resolved"):
            emit(res)
            sys.exit(2)
        cmd_remediate(cx, res["scan"]["id"], [s.upper() for s in a.severity], engines, a.out,
                      meta={"project": res["project"], "branch": res["branch"], "branch_selected_by": res.get("branch_selected_by"),
                            "branch_note": res.get("branch_note"), "scan": res["scan"]}, scope=a.scope,
                      generate=a.generate)


if __name__ == "__main__":
    main()
