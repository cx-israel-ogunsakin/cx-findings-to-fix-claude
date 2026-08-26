#!/usr/bin/env node
/**
 * Findings-to-Fix (ftf): pull Triage Assist CONFIRMED findings from Checkmarx One and
 * fetch platform-generated fixes from the Remediation Assist Agent API.
 *
 * Zero dependencies (Node 18+). Same behavior and same JSON output as ftf.py.
 *
 * Subcommands
 *   resolve   [--project NAME] [--branch NAME]
 *   remediate --scan-id ID [--severity A B] [--engine sast sca] [--out DIR]
 *   apply     [--manifest FILE] [--only 0,2] [--repo-root DIR]
 *   run       [resolve args] [remediate args]
 *
 * Auth: CX_APIKEY env var, or the cx CLI config (~/.checkmarx/checkmarxcli.yaml).
 * stdout: one JSON document. stderr: progress.
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { spawnSync } = require("child_process");

const USER_AGENT = "cx-findings-to-fix/0.1";
const POLL_INITIAL = 5_000, POLL_MAX = 30_000, POLL_TIMEOUT = 480_000, MAX_WORKERS = 8, HTTP_TIMEOUT = 60_000;
const FILE_MODE = 0o600;   // owner read/write only: patches and manifests carry tenant source code
const DIR_MODE = 0o700;
const HOME = path.normalize(path.resolve(os.homedir()));
const CWD = path.normalize(path.resolve(process.cwd()));

// ---------------------------------------------------------------- utilities
const log = (m) => process.stderr.write(`[ftf] ${m}\n`);
const emit = (o) => process.stdout.write(JSON.stringify(o, null, 2) + "\n");
function die(code, message, extra = {}) { emit({ ok: false, error: code, message, ...extra }); process.exit(1); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64json = (seg) => JSON.parse(Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));

function containedPath(candidate, ...roots) {
  const dest = path.normalize(path.resolve(candidate));
  for (const r of roots) {
    const root = path.normalize(path.resolve(r));
    const rel = path.relative(root, dest);
    if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) return dest;
  }
  throw new Error(`refusing path outside allowed roots: ${dest}`);
}
const readText = (p, roots) => fs.readFileSync(containedPath(p, ...roots), "utf8");
function writeWithMode(p, roots, data, mode = FILE_MODE) {
  // Open with an explicit mode and write through the descriptor. Default is owner-only
  // (.ftf outputs carry tenant source code); project files pass their own mode.
  const fd = fs.openSync(containedPath(p, ...roots), "w", mode);
  try { fs.writeSync(fd, data); fs.fchmodSync(fd, mode); } finally { fs.closeSync(fd); }
}
const writeText = (p, roots, t) => writeWithMode(p, roots, Buffer.from(t, "utf8"));
const writeBytes = (p, roots, b) => writeWithMode(p, roots, b);
const mkdirp = (p, mode = DIR_MODE) => fs.mkdirSync(p, { recursive: true, mode });
function ensureSelfIgnored(outDir) {
  // Drop a .gitignore containing `*` into the tool's own output folder, so .ftf
  // never shows up in the project's git status even before anyone edits .gitignore.
  const marker = path.join(outDir, ".gitignore");
  if (!fs.existsSync(marker)) writeText(marker, [outDir], "*\n");
}

async function httpRead(url, { method = "GET", body, headers = {}, timeout = HTTP_TIMEOUT } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const res = await fetch(url, { method, body, headers: { "User-Agent": USER_AGENT, ...headers }, signal: ctl.signal });
    const buf = Buffer.from(await res.arrayBuffer());
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from ${new URL(url).pathname}: ${buf.subarray(0, 200).toString()}`);
    return { status: res.status, body: buf };
  } finally { clearTimeout(t); }
}

// ---------------------------------------------------------------- auth
const KEY_LINE = /^\s*(cx_apikey|apikey|cx-apikey)\s*:\s*['"]?([A-Za-z0-9\-_.]{40,})['"]?\s*$/i;
function findApiKeyInCxConfig() {
  const cfg = path.join(HOME, ".checkmarx", "checkmarxcli.yaml");
  if (!fs.existsSync(cfg)) return null;
  for (const line of readText(cfg, [HOME]).split(/\r?\n/)) { const m = KEY_LINE.exec(line); if (m) return m[2]; }
  return null;
}

class CxClient {
  static async create() {
    const c = new CxClient();
    const apikey = process.env.CX_APIKEY || findApiKeyInCxConfig();
    if (!apikey) die("no_credential", "No Checkmarx One API key found. Set CX_APIKEY or run: cx configure set --prop-name cx_apikey --prop-value <key>");
    let iss;
    try { iss = b64json(apikey.split(".")[1]).iss; } catch (e) { log(`credential is not a JWT: ${e.message}`); die("bad_credential", "CX_APIKEY does not look like a Checkmarx One API key (expected a JWT)."); }
    const form = new URLSearchParams({ grant_type: "refresh_token", client_id: "ast-app", refresh_token: apikey }).toString();
    let tok;
    try {
      const { body } = await httpRead(`${iss}/protocol/openid-connect/token`, { method: "POST", body: form, headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 30_000 });
      tok = JSON.parse(body.toString()).access_token;
    } catch (e) {
      const msg = String((e && e.cause && (e.cause.code || e.cause.message)) || e.message || e);
      if (/CERT|certificate/i.test(msg)) die("tls_certificates", "This Node cannot verify HTTPS certificates (no CA bundle). Fix the CA bundle (NODE_EXTRA_CA_CERTS), or run the Python version: python3 ftf.py ...", { detail: msg.slice(0, 200) });
      if ((e && e.name === "AbortError") || /fetch failed|ENOTFOUND|ECONNREFUSED|EAI_AGAIN|ETIMEDOUT|ECONNRESET/i.test(msg)) die("network", `Could not reach Checkmarx One: ${msg}`);
      log(`token exchange failed: ${msg}`); die("auth_failed", "Token exchange failed. The API key may be revoked or expired.");
    }
    const claims = b64json(tok.split(".")[1]);
    c.base = process.env.CX_BASE_URL || claims["ast-base-url"];
    if (!c.base) die("no_base_url", "Could not determine the Checkmarx One base URL; set CX_BASE_URL.");
    c.tenant = claims.tenant_name || claims.azp || "?";
    c.headers = { Authorization: `Bearer ${tok}`, Accept: "application/json; version=1.0", "Content-Type": "application/json", "User-Agent": USER_AGENT };
    return c;
  }
  async call(method, p, body) {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), HTTP_TIMEOUT);
    try {
      const res = await fetch(this.base + p, { method, headers: this.headers, body: body === undefined ? undefined : JSON.stringify(body), signal: ctl.signal });
      const raw = await res.text();
      let parsed = {};
      try { parsed = raw ? JSON.parse(raw) : {}; } catch (e) { log(`non-JSON response (HTTP ${res.status}) from ${p}: ${e.message}`); parsed = { message: raw.slice(0, 300) }; }
      return [res.status, parsed];
    } catch (e) {
      // Same behavior as ftf.py: a transport failure is a network error, never a
      // tool result the caller could mistake for "not found".
      const msg = String((e && e.cause && (e.cause.code || e.cause.message)) || e.message || e);
      if (/CERT|certificate/i.test(msg)) die("tls_certificates", "This Node cannot verify HTTPS certificates (no CA bundle). Fix the CA bundle (NODE_EXTRA_CA_CERTS), or run the Python version: python3 ftf.py ...", { detail: msg.slice(0, 200) });
      if (e && e.name === "AbortError") die("network", `Checkmarx One did not answer within ${HTTP_TIMEOUT / 1000}s (${method} ${p}).`);
      die("network", `Could not reach Checkmarx One: ${msg}`);
    } finally { clearTimeout(t); }
  }
  get(p) { return this.call("GET", p); }
}

// ---------------------------------------------------------------- git helpers
function git(...args) {
  try {
    const r = spawnSync("git", args, { encoding: "utf8", timeout: 10_000 });
    if (r.error) { log(`git ${args.join(" ")} failed: ${r.error.message}`); return ""; }
    return r.status === 0 ? r.stdout.trim() : "";
  } catch (e) { log(`git ${args.join(" ")} failed: ${e.message}`); return ""; }
}
function localRepoGuess() {
  const url = git("remote", "get-url", "origin");
  const branch = git("rev-parse", "--abbrev-ref", "HEAD");
  const repo_root = git("rev-parse", "--show-toplevel");
  if (!url) return { remote_url: "", repo: "", parent: "", branch, repo_root };
  const parts = url.replace(/\/+$/, "").replace(/\.git$/, "").split(/[/:]/);
  return { remote_url: url, repo: parts[parts.length - 1] || "", parent: parts.length > 1 ? parts[parts.length - 2] : "", branch, repo_root };
}

// ---------------------------------------------------------------- resolve
async function exactProject(cx, name) {
  const [st, body] = await cx.get(`/api/projects?name=${encodeURIComponent(name)}&limit=5`);
  if (st !== 200) return null;
  return (body.projects || []).find((p) => p.name === name) || null;
}
const UNKNOWN_BRANCH = ".unknown";
const UNKNOWN_BRANCH_NOTE = "Checkmarx One files scans that were uploaded without branch information (zip uploads, some CI and monorepo setups) under the branch name '.unknown'. It is a normal, valid branch.";
async function latestCompletedScan(cx, projectId, branch) {
  const [st, scans] = await cx.get(`/api/scans?project-id=${projectId}&branch=${encodeURIComponent(branch)}&statuses=Completed&limit=1&sort=-created_at`);
  const scan = st === 200 ? (scans.scans || [])[0] : null;
  if (!scan) return null;
  return { id: scan.id, created_at: scan.createdAt, engines: scan.engines, source_origin: scan.sourceOrigin, source_type: scan.sourceType };
}
async function branchesWithScans(cx, projectId, maxScans = 200, maxBranches = 10) {
  // ONE paginated query over the project's most recent completed scans (each carries its branch),
  // instead of one call per branch. Only called when the cheap candidates have no scan.
  const seen = new Set(); const out = []; let offset = 0; const page = 100;
  while (offset < maxScans) {
    const [st, body] = await cx.get(`/api/scans?project-id=${projectId}&statuses=Completed&limit=${page}&offset=${offset}&sort=-created_at`);
    const scans = st === 200 ? (body.scans || []) : [];
    for (const sc of scans) {
      const b = sc.branch; if (b == null || seen.has(b)) continue; seen.add(b);
      out.push({ branch: b, latest_scan: { id: sc.id, created_at: sc.createdAt, engines: sc.engines, source_origin: sc.sourceOrigin, source_type: sc.sourceType }, note: b === UNKNOWN_BRANCH ? UNKNOWN_BRANCH_NOTE : null });
    }
    if (scans.length < page) break;
    offset += page;
  }
  return [out.slice(0, maxBranches), out.length];
}
async function cmdResolve(cx, project, branch, quiet = false) {
  const guess = localRepoGuess();
  const result = { ok: true, local: guess, tenant: cx.tenant, base_url: cx.base };
  const names = project ? [project] : [guess.parent && guess.repo ? `${guess.parent}/${guess.repo}` : null, guess.repo || null].filter(Boolean);
  const tried = []; let proj = null;
  for (const cand of names) { tried.push(cand); proj = await exactProject(cx, cand); if (proj) break; }
  if (!proj) {
    const needle = project || guess.repo || ""; let near = [];
    if (needle) { const [st, body] = await cx.get(`/api/projects?name-regex=${encodeURIComponent(needle)}&limit=10`); if (st === 200) near = (body.projects || []).map((p) => ({ name: p.name, id: p.id })); }
    Object.assign(result, { resolved: false, reason: "project_not_found", tried, candidates: near, next: "Ask the developer for the exact Checkmarx One project name (pick from candidates if listed) and rerun with --project." });
    if (!quiet) emit(result); return result;
  }
  result.project = { name: proj.name, id: proj.id };
  const pick = async (name, how) => { const scan = await latestCompletedScan(cx, proj.id, name); return scan ? [{ branch: name, latest_scan: scan, note: name === UNKNOWN_BRANCH ? UNKNOWN_BRANCH_NOTE : null }, how] : [null, null]; };
  let chosen = null, how = null;
  if (branch) {
    [chosen, how] = await pick(branch, "requested");
    if (!chosen) {
      const [withScans, nTotal] = await branchesWithScans(cx, proj.id);
      Object.assign(result, { resolved: false, reason: "no_completed_scan_on_branch", branch, branches_with_scans: withScans, branches_total: nTotal, next: "The requested branch has no completed scan. Show branches_with_scans (branch, latest scan date) as a numbered list, mention they can type another branch name, and ask which to use; rerun with --branch." });
      if (!quiet) emit(result); return result;
    }
  } else if (guess.branch && guess.branch !== "HEAD") {
    [chosen, how] = await pick(guess.branch, "matches_local_branch");
  }
  if (!chosen) {
    const [withScans, nTotal] = await branchesWithScans(cx, proj.id);
    Object.assign(result, { branches_with_scans: withScans, branches_total: nTotal });
    if (!withScans.length) { Object.assign(result, { resolved: false, reason: "no_completed_scans", next: "This project has no completed scans yet. Tell the developer; nothing to fix until a scan completes." }); if (!quiet) emit(result); return result; }
    if (nTotal === 1) { chosen = withScans[0]; how = "only_branch_with_scans"; }
    else {
      Object.assign(result, { resolved: false, reason: "branch_choice_needed", local_branch: guess.branch || null, suggested: withScans[0].branch, next: "The local branch has no completed scan but other branches do. Show branches_with_scans (the most recently scanned, up to 10) as a numbered list with each latest scan date, mark 'suggested' (the most recent) as the default, say they can also type any other branch name, and ask which to use; rerun with --branch." });
      if (!quiet) emit(result); return result;
    }
  }
  Object.assign(result, { resolved: true, branch: chosen.branch, branch_selected_by: how, branch_note: chosen.note, scan: chosen.latest_scan });
  if (!quiet) emit(result); return result;
}

// ---------------------------------------------------------------- findings + remediation
async function listConfirmed(cx, scanId, severities, engines) {
  const findings = []; let offset = 0; const page = 100;
  for (;;) {
    // One comma-joined severity parameter: the results API honors only the FIRST
    // value when the key is repeated, which silently dropped every non-CRITICAL finding.
    const qs = new URLSearchParams([["scan-id", scanId], ["limit", String(page)], ["offset", String(offset)], ["state", "CONFIRMED"], ["severity", severities.join(",")]]);
    const [st, body] = await cx.get(`/api/results/?${qs}`);
    if (st !== 200) die("results_failed", `/api/results returned HTTP ${st}: ${body.message}`);
    const batch = body.results || [];
    for (const r of batch) {
      const eng = (r.type || "").toLowerCase(); if (engines.length && !engines.includes(eng)) continue;
      const d = r.data || {}; const node = (d.nodes || [{}])[0] || {}; const vd = r.vulnerabilityDetails || {};
      findings.push({ alternate_id: r.alternateId || r.id, display_id: r.id, similarity_id: r.similarityId, engine: eng, severity: r.severity, state: r.state, status: r.status,
        query: d.queryName || vd.cveName || "", file: node.fileName || "", line: node.line, package: d.packageIdentifier, recommended_version: d.recommendedVersion, cwe: vd.cweId });
    }
    const total = body.totalCount || 0; offset += batch.length;
    if (!batch.length || offset >= total) break;
  }
  return findings;
}
// ---------------------------------------------------------------- scope (monorepos)
const normRel = (p) => (p || "").replace(/\\/g, "/").replace(/^\/+/, "");
function inferPathStrip(findings, repoRoot) {
  const files = findings.filter((f) => f.file).map((f) => normRel(f.file));
  if (!files.length || !repoRoot) return [0, 0];
  let best = [0, 0];
  for (let strip = 0; strip < 4; strip++) {
    let hits = 0;
    for (const fp of files) { const parts = fp.split("/"); if (parts.length <= strip) continue; if (fs.existsSync(path.join(repoRoot, ...parts.slice(strip)))) hits++; }
    const ratio = hits / files.length;
    if (ratio > best[1]) best = [strip, ratio];
    if (ratio >= 0.9) break;
  }
  return best;
}
function inferScopeSubpath(repoRoot) {
  try {
    const rr = path.normalize(path.resolve(repoRoot)), cwd = path.normalize(path.resolve(process.cwd()));
    const rel = path.relative(rr, cwd);
    if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) return "";
    return rel.split(path.sep).join("/");
  } catch (e) { return ""; }
}
function applyScope(findings, repoRoot, scope) {
  const [strip, ratio] = inferPathStrip(findings, repoRoot);
  const auto = scope == null || scope === "auto";
  const sub = auto ? inferScopeSubpath(repoRoot) : (scope === "all" ? "" : normRel(scope).replace(/\/+$/, ""));
  const info = { mode: scope || "auto", subpath: sub, path_strip: strip, path_match_ratio: Math.round(ratio * 100) / 100, findings_total: findings.length };
  if (!sub) { Object.assign(info, { findings_in_scope: findings.length, applied: false }); return [findings, info]; }
  const kept = findings.filter((f) => { if (!f.file) return true; const rel = normRel(f.file).split("/").slice(strip).join("/"); return rel === sub || rel.startsWith(sub + "/"); });
  const why = auto ? "the folder you have open" : "the scope you asked for";
  Object.assign(info, { findings_in_scope: kept.length, applied: true, note: `Showing findings under '${sub}' (${why}). The project has ${findings.length} in total; use --scope all to see everything.` });
  return [kept, info];
}

async function hasExistingFix(cx, scanId, f) {
  // HTTP 200 with a data payload means Remediation Assist already generated a fix (free to fetch);
  // 404 means generating it would consume Checkmarx Credits.
  const [st, body] = await cx.get(`/api/remediation/remediation-details/${scanId}/${encodeURIComponent(f.alternate_id)}`);
  if (st !== 200 || !body) return false;
  const res = (body.results || [])[0] || {};
  // A payload whose data carries an error is a FAILED generation, not a usable fix;
  // counting it as existing would block regeneration forever.
  return !!res.data && !res.data.error;
}
async function preflight(cx, scanId, findings) {
  const have = new Set();
  if (!findings.length) return have;
  await runPool(findings, async (f) => { if (await hasExistingFix(cx, scanId, f)) have.add(f.alternate_id); return null; }, MAX_WORKERS);
  return have;
}
async function initiate(cx, scanId, findings) {
  const buckets = {}; for (const f of findings) (buckets[f.engine] ||= []).push(f.alternate_id);
  const payload = { scanID: scanId, buckets: Object.entries(buckets).filter(([e]) => e === "sast" || e === "sca").map(([scannerType, resultIDs]) => ({ scannerType, resultIDs })) };
  if (!payload.buckets.length) return { submitted: 0 };
  const [st, body] = await cx.call("POST", "/api/remediation/remediate", payload);
  if (st !== 202) die("remediate_failed", `POST /api/remediation/remediate returned HTTP ${st}: ${body.message || JSON.stringify(body)}`, { hint: "HTTP 402/403 usually means Remediation Assist is not enabled or licensed for this tenant." });
  return { submitted: payload.buckets.reduce((n, b) => n + b.resultIDs.length, 0), job_id: body.remediationJobId, published: body.published, existing_state: body.existingState };
}
async function pollOne(cx, scanId, f) {
  const p = `/api/remediation/remediation-details/${scanId}/${encodeURIComponent(f.alternate_id)}`;
  const t0 = Date.now(); let delay = POLL_INITIAL;
  for (;;) {
    const [st, body] = await cx.get(p);
    const res = (body && body.results && body.results[0]) || {};
    const elapsed = Math.round((Date.now() - t0) / 1000);
    if (st === 200 && res.data) {
      const data = res.data;
      return { ...f, status: data.error ? "FAILED" : "READY", error: data.error || undefined, summary: data.summary, analysis: data.analysis || {}, pr_title: data.pr_title,
        file_changes: (data.file_changes || []).map((c) => ({ file_path: c.file_path, diff: c.diff, note: c.analysis })),
        tests: (((data.test_creation || {}).test_files) || []).map((t) => ({ file_path: t.file_path, framework: t.framework_used })),
        zip_url: (res.autoPr || {}).file_url, elapsed_s: elapsed };
    }
    if (res.jobStatus === "FAILED") return { ...f, status: "FAILED", error: "remediation job failed", elapsed_s: elapsed };
    if (st !== 200 && st !== 404) return { ...f, status: "FAILED", error: `HTTP ${st}: ${body.message}`, elapsed_s: elapsed };
    if (Date.now() - t0 > POLL_TIMEOUT) return { ...f, status: "TIMEOUT", error: `no result after ${POLL_TIMEOUT / 1000}s`, elapsed_s: elapsed };
    await sleep(delay); delay = Math.min(POLL_MAX, delay + 5_000);
  }
}
async function runPool(items, worker, size) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => { while (i < items.length) { const it = items[i++]; out.push(await worker(it)); } }));
  return out;
}
async function cmdRemediate(cx, scanId, severities, engines, outDir, quiet = false, meta = {}, scope = "auto", generate = false) {
  log(`listing CONFIRMED findings for scan ${scanId.slice(0, 8)}… (severity=${severities.join(",")}; engines=${engines.join(",") || "all"})`);
  let findings = await listConfirmed(cx, scanId, severities, engines);
  log(`${findings.length} confirmed finding(s)`);
  const repoRoot = git("rev-parse", "--show-toplevel") || CWD;
  let scopeInfo; [findings, scopeInfo] = applyScope(findings, repoRoot, scope);
  if (scopeInfo.applied) log(`scope '${scopeInfo.subpath}': ${scopeInfo.findings_in_scope} of ${scopeInfo.findings_total} finding(s)`);
  const manifest = { ok: true, scan_id: scanId, tenant: cx.tenant, base_url: cx.base, repo_root: repoRoot, scope: scopeInfo, filters: { state: ["CONFIRMED"], severity: severities, engines }, findings_total: findings.length, results: [], ...meta };
  if (!findings.length) { manifest.message = "No CONFIRMED findings match the filters. Nothing to fix."; await writeManifest(manifest, outDir, quiet); return manifest; }
  const have = await preflight(cx, scanId, findings);
  const need = findings.filter((f) => !have.has(f.alternate_id));
  manifest.credits = {
    findings_total: findings.length,
    fixes_already_generated: findings.length - need.length,
    fixes_to_generate: need.length,
    note: "Remediation Assist generates a fix for any finding that does not already have one, which consumes Checkmarx Credits. Fixes that already exist are fetched at no cost.",
  };
  log(`credits: ${findings.length - need.length} of ${findings.length} finding(s) already have a fix; ${need.length} would need generating`);
  let toFetch = findings;
  if (need.length && !generate) {
    // Never spend Checkmarx Credits without an explicit yes.
    manifest.credits.consent_required = true;
    manifest.submission = { submitted: 0, reason: "consent_required" };
    manifest.next = `${need.length} of ${findings.length} finding(s) have no fix yet. Generating them runs Checkmarx Remediation Assist and consumes Checkmarx Credits. Tell the developer the counts, ask whether to generate them, and on a yes rerun the same command with --generate. Fixes that already exist are included below and cost nothing.`;
    for (const f of need) manifest.results.push({ ...f, status: "NOT_GENERATED", note: "No fix exists yet; generating one consumes Checkmarx Credits." });
    log(`stopping before generating: rerun with --generate to spend credits on ${need.length} fix(es)`);
    toFetch = findings.filter((f) => have.has(f.alternate_id));
  } else if (need.length) {
    manifest.submission = await initiate(cx, scanId, need);
    manifest.credits.credits_consumed_for = need.length;
    log(`generating ${need.length} fix(es) (consumes Checkmarx Credits): ${JSON.stringify(manifest.submission)}`);
  } else {
    manifest.submission = { submitted: 0, note: "every finding already had a fix; nothing was generated" };
    log("every finding already had a fix; nothing generated, no credits consumed");
  }
  if (toFetch.length) {
    log(`fetching ${toFetch.length} fix(es) in parallel (up to ${MAX_WORKERS} workers)…`);
    const fetched = await runPool(toFetch, async (f) => { const r = await pollOne(cx, scanId, f); log(`  ${r.severity.padEnd(8)} ${r.engine.padEnd(4)} ${r.query.slice(0, 32).padEnd(32)} -> ${r.status} (${r.elapsed_s}s)`); return r; }, MAX_WORKERS);
    manifest.results.push(...fetched);
  }
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  manifest.results.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || a.query.localeCompare(b.query));
  manifest.ready = manifest.results.filter((r) => r.status === "READY").length;
  manifest.failed = manifest.results.length - manifest.ready;
  await writeManifest(manifest, outDir, quiet); return manifest;
}
async function savePlatformFiles(r, index, outDir) {
  // Download the platform's fully patched files while the signed zip URL is still fresh (minted once per
  // job, expires after about an hour). Reference copies for the agent under .ftf/platform/<index>/; never
  // written into the repo automatically.
  if (!r.zip_url) return;
  try {
    const { body } = await httpRead(r.zip_url);
    const names = listZipEntries(body);
    const base = path.join(outDir, "platform", String(index).padStart(2, "0"));
    for (const name of names) {
      if (name.endsWith("/")) continue;
      const data = readZipEntry(body, name); if (data === null) continue;
      const dest = containedPath(path.join(base, name), outDir);
      mkdirp(path.dirname(dest)); writeBytes(dest, [outDir], data);
    }
    r.platform_files_dir = base;
    for (const c of r.file_changes || []) if (names.includes(c.file_path)) c.platform_file = path.join(base, c.file_path);
  } catch (e) { log(`could not save platform files for result ${index}: ${e.message}`); r.platform_files_error = String(e.message).slice(0, 200); }
}
async function writeManifest(manifest, outDir, quiet) {
  if (outDir) {
    outDir = containedPath(outDir, CWD, HOME); mkdirp(outDir); ensureSelfIgnored(outDir);
    for (const [i, r] of manifest.results.entries()) {
      if (r.status !== "READY") continue;
      (r.file_changes || []).forEach((c, j) => { if (!c.diff) return;
        const p = path.join(outDir, `${String(i).padStart(2, "0")}-${j}-${path.basename(c.file_path || "change")}.patch`);
        writeText(p, [outDir], c.diff.endsWith("\n") ? c.diff : c.diff + "\n"); c.patch_path = p; });
      await savePlatformFiles(r, i, outDir);
    }
    const mp = path.join(outDir, "ftf-manifest.json"); manifest.manifest_path = mp; writeText(mp, [outDir], JSON.stringify(manifest, null, 2));
  }
  if (!quiet) emit(manifest);
}

// ---------------------------------------------------------------- apply
const HUNK = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;
function applyUnifiedDiff(original, diff) {
  // Strict single-file unified diff applier (for folders that are not git repos). Returns new text or null.
  const lines = original.split(/(?<=\n)/);
  const hunks = []; let cur = null;
  for (const raw of diff.split(/(?<=\n)/)) {
    if (/^(diff --git|index |--- |\+\+\+ )/.test(raw)) continue;
    const m = HUNK.exec(raw);
    if (m) { cur = { oldStart: parseInt(m[1], 10), lines: [] }; hunks.push(cur); continue; }
    if (cur && [" ", "-", "+", "\\"].includes(raw[0])) cur.lines.push(raw);
  }
  const out = []; let cursor = 0;
  const strip = (l) => l.replace(/\r?\n$/, "");
  for (const h of hunks) {
    const oldBlock = h.lines.filter((l) => l[0] === " " || l[0] === "-").map((l) => l.slice(1));
    const newBlock = h.lines.filter((l) => l[0] === " " || l[0] === "+").map((l) => l.slice(1));
    const want = h.oldStart - 1; let pos = null;
    const deltas = [0]; for (let k = 1; k < 50; k++) deltas.push(k, -k);
    for (const d of deltas) {
      const i = want + d;
      if (i < cursor || i < 0 || i + oldBlock.length > lines.length) continue;
      let ok = true;
      for (let j = 0; j < oldBlock.length; j++) if (strip(lines[i + j]) !== strip(oldBlock[j])) { ok = false; break; }
      if (ok) { pos = i; break; }
    }
    if (pos === null) return null;
    out.push(...lines.slice(cursor, pos), ...newBlock); cursor = pos + oldBlock.length;
  }
  out.push(...lines.slice(cursor));
  return out.join("");
}
function applyWithoutGit(diff, filePath, repoRoot) {
  const dest = containedPath(path.join(repoRoot, filePath), repoRoot);
  const original = fs.existsSync(dest) ? readText(dest, [repoRoot]) : "";
  const patched = applyUnifiedDiff(original, diff);
  if (patched === null) return false;
  // A project file keeps its own permissions; a new one gets the usual source modes.
  // Owner-only 0600 stays reserved for .ftf outputs, never the developer's sources.
  const mode = fs.existsSync(dest) ? (fs.statSync(dest).mode & 0o777) : 0o644;
  mkdirp(path.dirname(dest), 0o755);
  writeWithMode(dest, [repoRoot], Buffer.from(patched, "utf8"), mode); return true;
}
function listZipEntries(buf) {
  let eocd = buf.length - 22; while (eocd >= 0 && buf.readUInt32LE(eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error("bad zip");
  let ptr = buf.readUInt32LE(eocd + 16); const count = buf.readUInt16LE(eocd + 10); const names = [];
  for (let k = 0; k < count; k++) {
    if (buf.readUInt32LE(ptr) !== 0x02014b50) throw new Error("bad zip central dir");
    const nlen = buf.readUInt16LE(ptr + 28), xlen = buf.readUInt16LE(ptr + 30), clen = buf.readUInt16LE(ptr + 32);
    names.push(buf.subarray(ptr + 46, ptr + 46 + nlen).toString("utf8")); ptr += 46 + nlen + xlen + clen;
  }
  return names;
}
function readZipEntry(buf, wanted) {
  let eocd = buf.length - 22; while (eocd >= 0 && buf.readUInt32LE(eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error("bad zip");
  let ptr = buf.readUInt32LE(eocd + 16); const count = buf.readUInt16LE(eocd + 10);
  for (let k = 0; k < count; k++) {
    if (buf.readUInt32LE(ptr) !== 0x02014b50) throw new Error("bad zip central dir");
    const method = buf.readUInt16LE(ptr + 10), csize = buf.readUInt32LE(ptr + 20), nlen = buf.readUInt16LE(ptr + 28), xlen = buf.readUInt16LE(ptr + 30), clen = buf.readUInt16LE(ptr + 32), lho = buf.readUInt32LE(ptr + 42);
    const name = buf.subarray(ptr + 46, ptr + 46 + nlen).toString("utf8"); ptr += 46 + nlen + xlen + clen;
    if (name !== wanted) continue;
    const lnlen = buf.readUInt16LE(lho + 26), lxlen = buf.readUInt16LE(lho + 28); const start = lho + 30 + lnlen + lxlen; const data = buf.subarray(start, start + csize);
    if (method === 0) return Buffer.from(data); if (method === 8) return zlib.inflateRawSync(data); throw new Error(`unsupported zip method ${method}`);
  }
  return null;
}
function isGitTree(root) {
  const r = spawnSync("git", ["-C", root, "rev-parse", "--is-inside-work-tree"], { encoding: "utf8" });
  return r.status === 0 && r.stdout.trim() === "true";
}
function resolveRepoRoot(explicit, manifest) {
  const manifestParent = manifest.manifest_path ? path.dirname(path.dirname(manifest.manifest_path)) : null;
  for (const cand of [explicit, manifest.repo_root, git("rev-parse", "--show-toplevel"), manifestParent, CWD]) {
    if (cand && fs.existsSync(cand) && fs.statSync(cand).isDirectory()) { const root = path.normalize(path.resolve(cand)); return [root, isGitTree(root)]; }
  }
  die("no_target_folder", "Could not find the folder to apply fixes into. Run `apply` from the project root, or pass --repo-root.");
}
function overwriteFromPlatform(c, repoRoot) {
  // Explicit opt-in only: copy the platform's fully patched file over the local one.
  if (!c.platform_file || !fs.existsSync(c.platform_file)) return false;
  const dest = containedPath(path.join(repoRoot, c.file_path), repoRoot);
  // The project file keeps its own permissions; a new one gets the usual source modes.
  const mode = fs.existsSync(dest) ? (fs.statSync(dest).mode & 0o777) : 0o644;
  mkdirp(path.dirname(dest), 0o755);
  writeWithMode(dest, [repoRoot], fs.readFileSync(c.platform_file), mode); return true;
}
function loadManifestForApply(manifestPath, repoRoot) {
  manifestPath = path.normalize(path.resolve(manifestPath));
  if (!fs.existsSync(manifestPath)) {
    for (const base of [repoRoot, git("rev-parse", "--show-toplevel")]) {
      if (base && fs.existsSync(path.join(base, ".ftf", "ftf-manifest.json"))) { manifestPath = path.normalize(path.join(base, ".ftf", "ftf-manifest.json")); break; }
    }
  }
  if (!fs.existsSync(manifestPath)) die("no_manifest", `Manifest not found at ${manifestPath}. Run \`run\` first, or pass --manifest.`);
  return JSON.parse(readText(manifestPath, [path.dirname(manifestPath)]));
}
function cmdStage(manifestPath, only, repoRoot) {
  // Compute every fix against the CURRENT local files without writing anything into the workspace.
  // ready: exact diff fits; full patched content saved under .ftf/staged/ for the agent to propose as an editor edit.
  // needs_assist: local file drifted; agent places the change by hand.
  const manifest = loadManifestForApply(manifestPath, repoRoot);
  const [root, isGit] = resolveRepoRoot(repoRoot, manifest);
  const outDir = path.dirname(manifest.manifest_path || path.join(root, ".ftf"));
  const stagedDir = path.join(outDir, "staged");
  const report = { ok: true, repo_root: root, git_repo: isGit, ready: [], needs_assist: [], failed: [], skipped: [] };
  for (const [i, r] of (manifest.results || []).entries()) {
    if (only && !only.includes(i)) { report.skipped.push({ index: i, query: r.query }); continue; }
    if (r.status !== "READY") { report.skipped.push({ index: i, query: r.query, reason: r.status }); continue; }
    (r.file_changes || []).forEach((c, j) => {
      const filePath = c.file_path;
      const entry = { index: i, query: r.query, severity: r.severity, file: filePath, summary: r.summary, patch_path: c.patch_path };
      const diff = c.diff || "";
      if (!diff.trim() || !filePath) { entry.reason = "empty diff"; report.failed.push(entry); return; }
      let dest, original, patched;
      try {
        dest = containedPath(path.join(root, filePath), root);
        original = fs.existsSync(dest) ? readText(dest, [root]) : "";
        patched = applyUnifiedDiff(original, diff);
      } catch (e) { entry.reason = `could not read local file: ${e.message}`.slice(0, 300); report.failed.push(entry); return; }
      if (patched === null) {
        Object.assign(entry, { status: "NEEDS_ASSIST", reason: "local file differs from the scanned version; exact diff does not fit", platform_file: c.platform_file, analysis: r.analysis,
          hint: "Read patch_path (the intended change) and the local file, then propose the same change in the current code as an editor edit, preserving surrounding local edits." });
        report.needs_assist.push(entry); return;
      }
      mkdirp(stagedDir);
      ensureSelfIgnored(outDir);
      const staged = path.join(stagedDir, `${String(i).padStart(2, "0")}-${j}-${path.basename(filePath)}`);
      writeText(staged, [outDir], patched);
      const dl = diff.split("\n");
      Object.assign(entry, { status: "READY", exists: fs.existsSync(dest), patched_path: staged,
        lines_added: dl.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length,
        lines_removed: dl.filter((l) => l.startsWith("-") && !l.startsWith("---")).length,
        hint: "Propose an editor edit that replaces the full content of `file` with the content of `patched_path` (or apply the diff at `patch_path`). The developer accepts or rejects it in the editor. Do not write the file yourself with a terminal command." });
      report.ready.push(entry);
    });
  }
  report.tests = [...new Set((manifest.results || []).flatMap((r) => (r.tests || []).map((t) => t.file_path).filter(Boolean)))].sort();
  emit(report); return report;
}
async function cmdApply(manifestPath, only, repoRoot, overwrite = false) {
  // Tiered apply. Tier 1: exact diff (git apply --3way in a repo; strict built-in applier in a plain folder).
  // If that fails the file has drifted: report NEEDS_ASSIST with the patch, reference copy and analysis so the
  // agent places the same change by hand. --overwrite: explicit opt-in to copy the platform's full file instead.
  const manifest = loadManifestForApply(manifestPath, repoRoot);
  const [root, isGit] = resolveRepoRoot(repoRoot, manifest);
  const report = { ok: true, repo_root: root, git_repo: isGit, applied: [], needs_assist: [], failed: [], skipped: [] };
  if (!isGit) report.note = "Target folder is not a git repository; fixes are written directly to files (nothing is staged). Review with the editor's diff view.";
  for (const [i, r] of (manifest.results || []).entries()) {
    if (only && !only.includes(i)) { report.skipped.push({ index: i, query: r.query }); continue; }
    if (r.status !== "READY") { report.skipped.push({ index: i, query: r.query, reason: r.status }); continue; }
    for (const c of r.file_changes || []) {
      const filePath = c.file_path; const entry = { index: i, query: r.query, file: filePath }; const diff = c.diff || "";
      if (!diff.trim() || !filePath) { entry.reason = "empty diff"; report.failed.push(entry); continue; }
      let reason = "";
      if (isGit) {
        let proc;
        try { proc = spawnSync("git", ["apply", "--3way", "--whitespace=nowarn", "-"], { cwd: root, input: diff.endsWith("\n") ? diff : diff + "\n", encoding: "utf8" }); }
        catch (e) { entry.reason = `git apply could not run: ${e.message}`; report.failed.push(entry); continue; }
        if (proc.error) { entry.reason = `git apply could not run: ${proc.error.message}`; report.failed.push(entry); continue; }
        if (proc.status === 0) { entry.method = "git apply --3way"; report.applied.push(entry); continue; }
        reason = (proc.stderr || proc.stdout || "").trim().slice(0, 300);
      } else {
        try {
          if (applyWithoutGit(diff, filePath, root)) { entry.method = "unified diff applied directly (folder is not a git repo)"; report.applied.push(entry); continue; }
          reason = "diff context did not match the local file";
        } catch (e) { reason = `direct apply failed: ${e.message}`.slice(0, 300); }
      }
      if (overwrite) {
        try { if (overwriteFromPlatform(c, root)) { entry.method = "OVERWRITTEN with the platform's full patched file (local edits to this file were discarded; review carefully)"; report.applied.push(entry); continue; } }
        catch (e) { reason += `; overwrite failed: ${e.message}`; }
      }
      Object.assign(entry, {
        status: "NEEDS_ASSIST", reason, patch_path: c.patch_path, platform_file: c.platform_file, summary: r.summary, analysis: r.analysis,
        hint: "The local file differs from the scanned version, so the exact diff did not apply. Read patch_path (the intended change) and the local file, then make the same change in the current code with an editor edit, preserving surrounding local edits. platform_file is the platform's fully patched reference copy of the scanned version.",
      });
      report.needs_assist.push(entry);
    }
  }
  emit(report); return report;
}

// ---------------------------------------------------------------- test runner
const TEST_TIMEOUT = 300_000;
function detectTestRunner(repoRoot) {
  // The project's OWN runner. Returns [argv, label] or [null, reason]. Never installs or writes anything.
  // Windows: npm/mvn/gradle are .cmd/.bat launchers, so cmdTest spawns through a shell there.
  const win = process.platform === "win32";
  const pj = path.join(repoRoot, "package.json");
  if (fs.existsSync(pj)) {
    let d = {}; try { d = JSON.parse(readText(pj, [repoRoot])); } catch (e) { d = {}; }
    const script = ((d.scripts || {}).test || "").trim();
    if (!script || /^echo /i.test(script) || /no test specified/i.test(script) || script.toLowerCase() === "cx test") return [null, `package.json has no usable test script (scripts.test is ${JSON.stringify(script)})`];
    if (!fs.existsSync(path.join(repoRoot, "node_modules"))) return [null, "node_modules is not installed; run the project's install step (e.g. npm install) first"];
    return [["npm", "test", "--silent"], `npm test (${script})`];
  }
  const has = (f) => fs.existsSync(path.join(repoRoot, f));
  if (["pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"].some(has) || has("tests") || has("test")) {
    // On Windows a real Python is `python` or `py`; `python3` is usually the Store stub, which fails the probe.
    for (const py of win ? ["python", "py", "python3"] : ["python3"]) {
      const probe = spawnSync(py, ["-m", "pytest", "--version"], { encoding: "utf8" });
      if (probe.status === 0) return [[py, "-m", "pytest", "-q"], "python -m pytest"];
    }
    return [null, "pytest is not installed in this Python environment"];
  }
  if (has("pom.xml")) return [["mvn", "-q", "test"], "mvn test"];
  if (has("build.gradle") || has("build.gradle.kts")) {
    const wrapper = win ? "gradlew.bat" : "gradlew";
    return [has(wrapper) ? [win ? wrapper : "./gradlew", "test"] : ["gradle", "test"], "gradle test"];
  }
  if (has("go.mod")) return [["go", "test", "./..."], "go test ./..."];
  let subs = []; try { subs = fs.readdirSync(repoRoot).filter((d) => !d.startsWith(".") && fs.statSync(path.join(repoRoot, d)).isDirectory()).sort(); } catch (e) { subs = []; }
  const hints = subs.filter((d) => fs.existsSync(path.join(repoRoot, d, "package.json")) || fs.existsSync(path.join(repoRoot, d, "tests")));
  if (hints.length) return [null, `no test runner at the project root; found test setups under ${hints.slice(0, 4).join(", ")}. Open that folder (or rerun with --repo-root) to run its tests`];
  return [null, "no recognised test runner (package.json scripts.test, pytest, maven, gradle, go)"];
}
function cmdTest(manifestPath, repoRoot, onlyFiles) {
  const manifest = loadManifestForApply(manifestPath, repoRoot);
  const [root] = resolveRepoRoot(repoRoot, manifest);
  const platformTests = [...new Set((manifest.results || []).flatMap((r) => (r.tests || []).map((t) => t.file_path).filter(Boolean)))].sort();
  const present = platformTests.filter((t) => fs.existsSync(path.join(root, t)));
  const [argv, label] = detectTestRunner(root);
  const report = { ok: true, repo_root: root, platform_tests: platformTests, platform_tests_present: present };
  if (!argv) { Object.assign(report, { ran: false, reason: label, note: "The project's test runner is not set up, so the tests were not run. Tell the developer exactly this and stop; do not install dependencies, edit package files, or create another runner." }); emit(report); return report; }
  let cmd = argv; if (onlyFiles && onlyFiles.length && argv[1] === "-m" && argv[2] === "pytest") cmd = argv.concat(onlyFiles.filter((f) => fs.existsSync(path.join(root, f))));
  // shell on Windows: npm/mvn/gradle are .cmd/.bat launchers, which Node refuses to spawn directly.
  let proc;
  try {
    proc = spawnSync(cmd[0], cmd.slice(1), { cwd: root, encoding: "utf8", timeout: TEST_TIMEOUT, shell: process.platform === "win32" });
  } catch (e) {
    Object.assign(report, { ran: false, runner: label, reason: `could not start the runner: ${e.message}` }); emit(report); return report;
  }
  if (proc.error && proc.error.code === "ETIMEDOUT") { Object.assign(report, { ran: true, runner: label, passed: false, reason: `timed out after ${TEST_TIMEOUT / 1000}s` }); emit(report); return report; }
  if (proc.error) { Object.assign(report, { ran: false, runner: label, reason: `could not start the runner: ${proc.error.message}` }); emit(report); return report; }
  const out = (proc.stdout || "") + (proc.stderr || "");
  Object.assign(report, { ran: true, runner: label, exit_code: proc.status, passed: proc.status === 0, output_tail: out.slice(-3000) });
  emit(report); return report;
}

// ---------------------------------------------------------------- main (tiny arg parser, no deps)
function parseArgs(argv) {
  const out = { _: [] }; let key = null;
  for (const a of argv) {
    if (a.startsWith("--")) { key = a.slice(2).replace(/-/g, "_"); out[key] = out[key] || []; continue; }
    if (key) out[key].push(a); else out._.push(a);
  }
  return out;
}
(async () => {
  const a = parseArgs(process.argv.slice(2)); const cmd = a._[0];
  const one = (k, d) => (a[k] && a[k][0]) || d;
  const many = (k, d) => (a[k] && a[k].length ? a[k] : d);
  if (!["resolve", "remediate", "run", "stage", "test", "apply"].includes(cmd)) { process.stderr.write("usage: ftf.js resolve|remediate|run|stage|test|apply [options]\n"); process.exit(2); }
  if (cmd === "test") { cmdTest(one("manifest", ".ftf/ftf-manifest.json"), one("repo_root"), many("only", [])); return; }
  if (cmd === "stage") { cmdStage(one("manifest", ".ftf/ftf-manifest.json"), a.only ? a.only[0].split(",").map(Number) : null, one("repo_root")); return; }
  if (cmd === "apply") { await cmdApply(one("manifest", ".ftf/ftf-manifest.json"), a.only ? a.only[0].split(",").map(Number) : null, one("repo_root"), !!a.overwrite); return; }
  const cx = await CxClient.create();
  const severities = many("severity", ["CRITICAL", "HIGH"]).map((s) => s.toUpperCase());
  const engines = many("engine", ["sast"]).map((e) => e.toLowerCase());
  const out = one("out", ".ftf"); const scope = one("scope", "auto"); const generate = !!a.generate;
  if (cmd === "resolve") await cmdResolve(cx, one("project"), one("branch"));
  else if (cmd === "remediate") { const sid = one("scan_id"); if (!sid) die("missing_arg", "--scan-id is required"); await cmdRemediate(cx, sid, severities, engines, out, false, {}, scope, generate); }
  else { const res = await cmdResolve(cx, one("project"), one("branch"), true); if (!res.resolved) { emit(res); process.exit(2); }
    await cmdRemediate(cx, res.scan.id, severities, engines, out, false, { project: res.project, branch: res.branch, branch_selected_by: res.branch_selected_by, branch_note: res.branch_note, scan: res.scan }, scope, generate); }
})().catch((e) => die("unexpected", e.message));
