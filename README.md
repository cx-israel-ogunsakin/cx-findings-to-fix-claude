# Findings-to-Fix for Claude Code

Fix the security findings Checkmarx has already confirmed in your code, from
your terminal or editor, with Claude Code.

You run one command. Checkmarx generates the fix. Claude shows you each change
as a diff and you accept or reject it. That is the whole thing.

Using GitHub Copilot instead? Use
[cx-findings-to-fix](https://github.com/cx-israel-ogunsakin/cx-findings-to-fix),
the Copilot version of this same plugin.

<p align="center">
  <a href="docs/findings-to-fix-architecture-animated.html">
    <img src="docs/images/architecture.gif" width="720" alt="Findings-to-Fix architecture: the ten steps from a scan on Checkmarx One to a reviewed fix">
  </a>
  <br>
  <sub>The ten steps, from a scan to a reviewed fix. Interactive version:
  <a href="docs/findings-to-fix-architecture-animated.html">docs/findings-to-fix-architecture-animated.html</a>
  (download and open in a browser). Full guide:
  <a href="docs/Findings-to-Fix.pdf">docs/Findings-to-Fix.pdf</a>.</sub>
</p>

## Getting started

You need three things once. After that it is just running the command.

### 1. A Checkmarx One API key on your machine

Ask your Checkmarx admin for an API key. Then either

- put it in your shell profile: `export CX_APIKEY=<your key>`, or
- if you already use the Checkmarx `cx` command line tool:
  `cx configure set --prop-name cx_apikey --prop-value <your key>`

Findings-to-Fix reads it from either place. It never shows the key to Claude.

### 2. Python or Node on your machine

Either one works. Most Macs and Linux machines already have Python 3. On
Windows, if you have `python3` or `node` in a terminal, you are set.

### 3. Install the plugin

```
claude plugin marketplace add cx-israel-ogunsakin/cx-findings-to-fix-claude
claude plugin install cx-findings-to-fix@cx-findings-to-fix-claude
```

(For a private copy of this repository, use its Git URL or a local folder path
in the first command.) You will see a short "Findings-to-Fix is installed" note
when a session starts.

## Using it

1. Open a terminal in the project you want to fix (or open it in VS Code or
   JetBrains with the Claude Code extension) and start `claude`.
2. Type `/cx-f`, press Tab to complete, then Enter. You can add the project
   name and branch after the command to skip the questions:
   `/cx-findings-to-fix CxRW-Sandbox/ProjectHub9 feat/update-routes`

Claude will:

- work out which Checkmarx project and branch this is. If it cannot tell from
  your git setup, it lists the likely projects and asks you to pick one, then
  the branches that have scans. It never guesses.
- fetch the fixes from Checkmarx (a couple of minutes the first time, seconds
  after that).
- show you a table of the confirmed findings and ask which to apply.
- propose each change as an edit you accept or reject, file by file.
- explain what each fix does and why.
- offer to run the tests Checkmarx generated for the fix.

Nothing is committed or pushed. You review, then commit as usual.

## Good to know

- Only findings that Checkmarx AI Auto Triage has marked **Confirmed**, at
  critical or high severity, are fixed. Nothing else is touched.
- If you edited a file near the vulnerable code since the last scan, Claude
  places the fix into your current code by hand instead of applying it
  blindly, and tells you so. Your edits stay.
- It works whether your project folder is a git clone or a plain folder.
- Package (SCA) fixes are supported but off by default. Ask Claude to
  "include package fixes" if you want them.
- The first run asks you to allow the plugin's command; that is Claude Code's
  normal permission prompt for running a tool.
- If something is missing (no API key, expired key, feature not enabled on
  your tenant), Claude tells you exactly what and how to fix it.

## For admins: rolling it out to a team

Put this repository somewhere your developers can reach (GitHub, Bitbucket, an
internal Git server). Each developer runs the two install commands once with
that URL. Claude Code's managed settings can pre-approve the marketplace for
everyone.

## What is in this repository

| Path | What it is |
|---|---|
| `.claude-plugin/plugin.json` | Tells Claude Code this is a plugin |
| `.claude-plugin/marketplace.json` | Lets this repository be added as a marketplace |
| `commands/cx-findings-to-fix.md` | The `/cx-findings-to-fix` command and its instructions |
| `agents/findings-to-fix.md` | A subagent with the same instructions |
| `skills/fix-confirmed-findings/SKILL.md` | The same instructions as a skill |
| `skills/fix-confirmed-findings/ftf.py`, `ftf.js` | The tool that talks to Checkmarx (Python and Node versions, identical) |
| `hooks/` | The one-line "installed" note at session start |
| `docs/` | The guide (`Findings-to-Fix.pdf`), `how-it-works.md`, the interactive architecture page, and screenshots |

Nothing runs on a server. Nothing is installed besides this folder. The tool
(`ftf.py` / `ftf.js`) is identical to the one in the Copilot repository; that
repository is where it is maintained.

## Support

Questions and issues: open an issue in this repository.
