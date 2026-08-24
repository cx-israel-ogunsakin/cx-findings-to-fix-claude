# Findings-to-Fix: how it works

Findings-to-Fix builds on Checkmarx One Triage Assist and Remediation Assist.
Triage Assist has already evaluated the findings on the platform using
Attackability-based context (reachability, exploitability, code context, policy
signals) and confirmed the ones that require action. The plugin takes only those
confirmed findings, asks Remediation Assist to generate the review-ready fix, and
brings it to the developer in Claude Code as a change they review and can
undo. Remediation Assist can open review-ready fix pull requests
for supported GitHub Code Repository Integration projects; for every other
project type, this plugin is how that fix reaches the editor. The agent
proposes; the developer approves. (A GitHub Copilot version of the same plugin
exists as a separate repository.) This document describes the pieces, the sequence,
and the boundaries.

## The pieces

**On the Checkmarx One platform**

- Scans run on each push or pull request, triggered from the customer's CI/CD
  pipeline against the code in Bitbucket.
- Triage Assist evaluates eligible findings using Attackability-based context
  (reachability, exploitability, code context, policy signals), on the platform
  and on the cadence AppSec configures. It marks findings that require action
  **Confirmed** and theoretical ones **Proposed Not Exploitable**; previously
  triaged findings are left unchanged. Nothing in the plugin changes these
  verdicts.
- Remediation Assist generates a code fix for a finding on request: the changed
  files as diffs, a short explanation (what, why, how), and unit tests that
  exercise the fix.
- The Checkmarx One REST API is how the plugin reaches all of the above.

**On the developer's machine**

- Claude Code, in a terminal or through its VS Code and JetBrains extensions.
- The Findings-to-Fix plugin, installed once from a Git repository. It
  provides the `/cx-findings-to-fix:fix` command, a subagent, a skill with the
  same instructions, and one small tool (`ftf`, shipped in both Python and
  Node so either runtime works) that talks to the Checkmarx API.
- The developer's Checkmarx One API key, stored in their shell profile or in
  the Checkmarx `cx` CLI configuration. The tool exchanges it for a short-lived
  token in memory. The key never appears in the assistant's conversation.

## The plugin's anatomy

Each file has exactly one job.

```
cx-findings-to-fix-claude/
├── .claude-plugin/
│   ├── plugin.json           the manifest: name, version, description
│   └── marketplace.json      makes this repository installable as a marketplace
├── commands/fix.md           the /cx-findings-to-fix:fix command: the protocol
├── agents/findings-to-fix.md a subagent carrying the same protocol, for delegation
├── skills/fix-confirmed-findings/
│   ├── SKILL.md              the same protocol as a skill, triggered by phrasing
│   ├── ftf.py                the tool: every deterministic step
│   └── ftf.js                the identical tool for machines without Python
├── hooks/
│   ├── hooks.json            runs check-auth.sh at session start
│   └── check-auth.sh         the session note and the API key warning
└── docs/                     this document, the guide, the architecture page
```

Markdown decides; code does. The command, the subagent, and the skill are one
protocol written for three entry points, and they carry all of the judgment:
ask rather than guess, propose rather than write, offer the tests once. The
tool carries none: it talks to the Checkmarx One API, computes fixes against
the developer's current files, applies nothing on its own, and prints one JSON
document per subcommand. Everything below follows from that split. It is also
why the assistant's cost stays flat as findings grow: the model reads a
manifest and the diffs it proposes, never the whole result set.

## The sequence

1. **The developer asks.** In Claude Code, the developer runs
   `/cx-findings-to-fix:fix`, optionally followed by the project name and
   branch.
2. **The assistant runs the tool.** The tool reads the project's git remote
   and looks the project up in Checkmarx One; if the name does not match, it
   returns the closest projects and the developer picks. It then chooses the
   scan: if exactly one branch has completed scans it uses that one and says
   so (monorepos and zip uploads usually have a single branch, which Checkmarx
   One names `.unknown`); if the developer's local branch has a scan it uses
   it; otherwise it lists the branches that have scans, with dates, and the
   developer picks. The tool never guesses.
   In a monorepo, if the developer has one service's folder open rather than
   the whole repository, the tool limits the findings to that folder and says
   how many the project has in total.
3. **The tool fetches the fixes.** It lists the findings on the latest
   completed scan that are Confirmed at critical or high severity and checks
   which of them already have a fix. Fixes that already exist are fetched at
   no cost and come back in seconds. If any finding has no fix yet, the
   assistant stops and asks first: generating a fix runs Remediation Assist
   and consumes Checkmarx Credits, so nothing is generated without a yes.
   Fresh fixes take two to three minutes and are fetched in parallel. The
   result is a manifest: per finding, the changed files as diffs, the
   explanation, and the generated tests.
4. **The assistant shows the findings** as a table and asks which to apply.
5. **The tool computes each fix against the developer's current files**
   without writing anything. For each changed file it produces the complete
   new content, or reports that the local file has changed since the scan so
   the exact diff no longer fits.
6. **The assistant applies each fix as an edit.** Each change lands file by
   file; the developer reviews afterwards, in the Source Control view for a
   git repository or through the conversation's diff cards, and can undo any
   of them. This is the same whether the project is a git clone or a plain
   folder.
7. **Files that changed since the scan** are handled differently: the
   assistant reads the intended change and the current file, makes the same change where
   the code now lives, keeps the developer's other edits, and says plainly that
   this fix was placed by hand and deserves a closer look. It never
   overwrites a whole file on its own.
8. **The assistant explains** each fix (what, why, how) and names the tests
   Remediation Assist generated.
9. **The assistant offers to run those tests** and does so only if the developer says
   yes.
10. **The developer commits as usual.** The plugin never commits or pushes.

## Where the credential goes and does not go

| Credential | Lives | Used by | Never reaches |
|---|---|---|---|
| Checkmarx One API key | shell profile or `cx` CLI config on the workstation | the `ftf` tool, which exchanges it for a short-lived token in memory | the assistant's conversation, Anthropic |
| Claude Code session | Claude Code's sign-in | Claude Code | Checkmarx |
| CI/CD credential that triggers scans | the CI/CD system | the pipeline | the developer's machine |

## What can and cannot happen

- The plugin reads findings and fetches fixes. It cannot change a finding's
  state, trigger a scan, or touch Checkmarx configuration.
- A fix is generated only after the developer agrees to spend Checkmarx
  Credits on it. Fixes that already exist are fetched at no cost.
- The tool keeps its working files in a `.ftf` folder at the project root; it
  can be deleted at any time and belongs in `.gitignore`.
- Every change to code arrives as an editor edit the developer can review and
  undo. The tool writes nothing into the project on its own during the normal
  flow.
- The plugin never commits or pushes.
- Only Confirmed critical and high findings are considered. Package (SCA)
  fixes are supported and off by default.
- Nothing runs on a server. Nothing is installed besides the plugin folder.

## Rolling out to a team

Host the plugin repository somewhere developers can reach. Each developer
adds the repository as a marketplace and installs from it
(`claude plugin marketplace add`, `claude plugin install`). Claude Code's
managed settings can pre-approve the marketplace for everyone.

Per developer, one time: an API key, and Python 3 or Node on the machine.
Claude Code's Bash tool must be allowed; the first run asks the developer to
permit the plugin's command.
