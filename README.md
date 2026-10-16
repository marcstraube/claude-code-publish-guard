# publish-guard

![CI](https://github.com/marcstraube/claude-code-publish-guard/actions/workflows/ci.yml/badge.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A [Claude Code](https://claude.com/claude-code) plugin that makes the moment of
publishing deliberate. It hooks the Bash tool and blocks every command that
sends text to a remote until two things hold:

1. **The text passed a denylist.** The hook extracts what the command would
   publish and scans it for your hostnames, usernames, addresses, local paths,
   self-referential phrases and internal status words. A hit blocks the command.
   Nothing overrides it; the text has to change.
2. **Claude acknowledged it explicitly.** Claude must print a public-content
   checklist in the conversation and record a single-use acknowledgement,
   bound to the session, the action and the repository. Without it the command
   does not run.

The threat model is a forgetful author, not an adversary. Public repositories
keep every edit forever: a force-push hides a commit from the branch tip, but
the SHA stays reachable through PR events, reflogs, webhooks and the API.
Catching a hostname in an issue body *before* `gh issue create` runs is the
only fix that works.

## What is gated

| Command | Text that is inspected |
| --- | --- |
| `git commit` | `-m` (repeated), `-F file`, `-F -` with heredoc / here-string / `echo` or `printf` pipe, `--amend` (HEAD message), `-C`/`-c`/`--fixup`/`--squash` (reused message), `--trailer`, `-t template` |
| `git push` | message of every commit not yet on the target remote, branch name, refspecs, annotated tag messages for `--tags`, `--follow-tags`, `--mirror` or an explicit tag, `--push-option` values |
| `gh pr create` | title, body, body file, commits used by `--fill*`, head branch name, plus the implicit push |
| `gh pr merge` | the PR title, body and commit messages **as they are on GitHub right now** (`gh pr view --json`), plus `--subject`/`--body` overrides. No network, no merge |
| `gh pr edit / comment / review / close / reopen` | every argument after the verb and the content of `-F`/`--body-file` |
| `gh issue create / edit / comment / close / reopen` | same |
| `gh release create / edit` | notes, notes file, title, `--notes-from-tag` message, commits used by `--generate-notes` |
| `gh api` with a non-GET method or any `-f`/`-F`/`--input` field | field values, `@file` contents, `--input` body |
| `gh repo edit / create / rename`, `gh gist create / edit` | arguments and gist file contents |
| `glab mr / issue / release ...` | the GitLab equivalents (no live fetch for `mr merge`) |

Commands are parsed, not pattern-matched. `git -C dir -c k=v commit`,
`git --git-dir .git --work-tree . push`, `\git`, `/usr/bin/git`, `env X=1 git`,
`command git`, `sudo -u u git`, `xargs git`, `timeout 60 git`, `bash -c "git ..."`,
`eval`, `bash <<'EOF' ... EOF`, `$(git ...)` and backticks are all recognized.
`git commit --help`, `grep "git commit" file`, `man git-commit` and a heredoc
that merely *writes* a file containing `git push` are not gated.

Commands that cannot be inspected are blocked with an explanation: a commit
message built from `$VAR` or an unresolved `$(...)`, `bash -c "$CMD"`,
`curl ... | bash`, and inline Python/Perl/Node that mentions git or gh.

Out of scope: registry publishing (`npm publish`, `ansible-galaxy collection
publish`) and secrets inside file diffs. Use gitleaks or similar for the latter.

## Installation

Requirements: Python 3.10+ and git. The hook itself calls `gh` only for
`gh pr merge`, to fetch the live PR text. `glab` commands are inspected from
their arguments alone, so neither CLI is needed for the gate as such.

**Via the marketplace** (inside Claude Code):

```
/plugin marketplace add marcstraube/claude-code-publish-guard
/plugin install publish-guard@marcstraube
```

**From a clone**, for hacking on it:

```bash
git clone https://github.com/marcstraube/claude-code-publish-guard.git ~/src/claude-code-publish-guard
ln -s ~/src/claude-code-publish-guard ~/.claude/skills/publish-guard
```

Claude Code loads plugins from `~/.claude/skills/<name>/` automatically at the
next session start as `publish-guard@skills-dir`. For a one-off try:
`claude --plugin-dir ~/src/claude-code-publish-guard`.

Check that it is active with `/hooks` (a PreToolUse hook on `Bash` from
`publish-guard`). In a session that was already running, `/reload-plugins`
activates it; until then that session has no gate.

### Your private denylist

On first use the hook creates `~/.config/claude-code-publish-guard/denylist.txt`
(mode 0600) from `templates/denylist.example.txt`. Put your hostnames, internal
domains, usernames and real names there, one regular expression per line, with
word boundaries:

```
[always]
\bbastion01\b
\bhome\.arpa\b
\bjdoe\b

[messages-only]
\bthe customer\b
```

The directory can be changed through the plugin's `config_dir` option
(`claude plugin configure publish-guard@marcstraube`, or `@skills-dir` for the
symlink install). Keep the file out of every repository, including dotfiles.

`patterns/builtin.txt` ships generic patterns: private IP ranges, e-mail
addresses (except noreply bots), home directory paths, vault variable names,
copied shell prompts, and the phrases from the checklist ("on my workstation",
"still in dev", "WIP", "out of scope", ...).

## How a publish looks in a session

1. Claude runs `git commit -m "..."`. The hook blocks it and returns the
   checklist plus the exact acknowledgement command.
2. Claude quotes the full text to be published, prints the checklist with every
   box ticked and a one-line justification, and runs (separate Bash call):
   ```
   ~/.claude/skills/publish-guard/bin/publish-guard-ack commit --repo /path/to/repo
   ```
3. Claude re-runs the commit. The hook extracts the message, scans it, finds
   the acknowledgement, consumes it, and lets the command through.

A second publish needs a fresh checklist and a fresh acknowledgement.
Acknowledgements expire after 10 minutes and are stored under
`$XDG_RUNTIME_DIR/publish-guard/<session-id>/`, so parallel sessions and other
users on the machine cannot consume each other's. Every hook run sweeps that
directory: expired acknowledgements of any session are deleted and empty
session directories older than the TTL are removed, so finished sessions leave
nothing behind.

`commit push` may be acknowledged together when one checklist covers both.
Because the gate blocks the whole Bash command, staging must happen in its own
call: `git add X && git commit ...` is blocked as a unit and the `git add` never
ran. The block message says so.

### Tools

- `bin/publish-guard-ack <action>... [--repo <dir|owner/repo>]`, `--status`
- `bin/publish-guard-check <file|->` scans a draft against the denylists
- `bin/publish-guard-check --classify '<command>'` shows what would be gated
- `$CLAUDE_PLUGIN_DATA/audit.log` records every decision (timestamp, session,
  action, repository, decision, first 200 characters of the command; never the
  published text). The directory lives under `~/.claude/plugins/data/`, for
  the symlink install as `publish-guard-skills-dir/`. Beyond 1 MB the file is
  rotated once to `audit.log.1`.

## Design notes

- **Fail closed.** Parse errors, unreadable files, a `gh pr view` without
  network: the command is blocked with the reason. `onFailure: "block"` is set
  in `hooks/hooks.json` for Claude Code 2.1.295+; the script itself exits 2 on
  any internal error for older versions.
- **Denylist before acknowledgement.** A denylist hit is reported first, and it
  does not consume the acknowledgement, so Claude fixes the text and retries
  without printing the checklist twice.
- **No allowlist, no bypass flag.** A false positive is solved by rewording or
  by refining the pattern in the private denylist.
- **The hook never writes to the repository** and never fetches. Push
  inspection uses the local tracking refs (`rev-list HEAD --not --remotes=<r>`),
  which can only over-approximate.
- **Author trailers are skipped.** `Signed-off-by:` and `Co-authored-by:` lines
  carry identities that are in the commit metadata anyway.

## Development

```bash
python3 -m unittest discover -s tests -v
shellcheck bin/*
claude plugin validate . --strict
```

The test suite covers the shell scanner, classification of every gated and
non-gated shape listed above, extraction against a fake runner, the denylists,
the acknowledgement store (including the bash script), and end-to-end hook
decisions against a temporary git repository with a bare remote.

## Roadmap

- Optional scan of added diff lines for the `[always]` section, enabled per
  repository (hostnames in a private inventory repository are legitimate).
- Strict mode: the block message carries a hash of the extracted text and the
  acknowledgement binds to it.
- Git-level `commit-msg` / `pre-push` hooks as a layer independent of Claude.

## License

MIT, see `LICENSE`.
