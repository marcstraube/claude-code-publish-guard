---
name: publish-guard
description: Mandatory procedure before any command that publishes text to a remote - git commit, git push, gh pr create/merge/edit/comment/review/close, gh issue create/edit/comment/close, gh release create/edit, gh api writes, gh repo edit, gh gist, and the glab equivalents. Use it whenever you are about to run one of these, when a Bash call was blocked with "publish-guard: BLOCKED", or when the user asks to commit, push, open a PR or issue, cut a release, or comment on GitHub.
---

# publish-guard

A PreToolUse hook blocks every Bash command that publishes text until two
conditions hold:

1. **Denylist (automatic, hard).** The hook extracts the text the command
   would publish (commit message, PR/issue title and body, release notes,
   comment, `gh api` fields, unpushed commit messages for a push, the live PR
   title/body/commits for a merge) and scans it against
   `${CLAUDE_PLUGIN_ROOT}/patterns/builtin.txt` and the user's private
   denylist. A hit blocks the command. Nothing overrides it; change the text.
2. **Acknowledgement (explicit, visible).** You must print the checklist and
   record an acknowledgement with `publish-guard-ack` before the command runs.
   Acknowledgements are single-use, bound to this session, the action and the
   repository, and expire after 10 minutes.

Threat model: the author is forgetful, not adversarial. Public repositories keep
every edit forever; force-pushes and edits do not remove a leak. The gate makes
the moment of publishing deliberate and leaves a visible audit trail in the
conversation.

## The procedure, every time

Do all three steps in the **same assistant message**, in this order.

### Step 1: quote the text and print the checklist

Above any tool call, paste the full text that will be published, then the
checklist with every box ticked and a one-line justification per item:

```
${CLAUDE_PLUGIN_ROOT}/skills/publish-guard/checklist.md
```

Read that file and reproduce it verbatim with the placeholders filled in. If a
box cannot be ticked honestly: stop, rewrite the text, start the checklist from
the top.

For `gh pr merge` the published text is the PR title and body **as they are on
GitHub right now** (they may have been edited in the web UI). Fetch them with
`gh pr view <n> --json title,body` and quote that, not what you wrote when the
PR was created.

### Step 2: record the acknowledgement (separate Bash call)

```bash
${CLAUDE_PLUGIN_ROOT}/bin/publish-guard-ack <action>... --repo <path|owner/repo>
```

Actions: `commit push pr-create pr-merge pr-edit pr-comment pr-review pr-close
issue-create issue-edit issue-comment issue-close release api repo-edit gist`.
Several actions may be acknowledged at once when one checklist covers them
(`commit push` for the usual commit-then-push flow). `--repo` is the repository
directory (default: the current one) or the `owner/repo` you pass to `gh -R`.
When the hook blocks a command it prints the exact ack command to run.

### Step 3: run the publish command unchanged

The hook finds the acknowledgement, consumes it and lets the command through.
A second publish needs a fresh checklist and a fresh ack.

## Rules that avoid wasted round-trips

- **Stage separately.** The gate blocks the whole Bash command. `git add X &&
  git commit ...` is blocked as a unit, so the `git add` never ran. Stage in its
  own call, confirm with `git status --short`, then commit on its own.
- **Write the text literally.** Messages built from shell variables or
  unresolved `$(...)` cannot be inspected and are blocked. Use `-m "..."`, a
  heredoc (`-F -` with `<<'EOF'`, or `-m "$(cat <<'EOF' ... EOF)"`), or a file.
- **Run git/gh directly.** `bash -c "..."`, `eval`, piped scripts and inline
  Python/Perl that call git or gh are either inspected recursively or blocked.
- **Dry-run first when unsure.** `${CLAUDE_PLUGIN_ROOT}/bin/publish-guard-check
  - <<'EOF' ... EOF` scans a draft; `publish-guard-check --classify '<cmd>'`
  shows what a command would be gated as.
- **No exceptions for private repositories.** Private code gets extracted into
  public collections and copied into public repos later; the commit message
  travels with it.

## What the checklist is about

Keep published text free of: your hostnames and internal FQDNs; usernames,
real names and e-mail addresses beyond the git author identity; IP addresses,
topology, VPN details; inventory or vault variable names and values; local
paths outside the repository; output copied from runs against real hosts;
self-referential phrases ("in inventory", "we have", "on my workstation");
status of internal things ("still in dev", "WIP", "haven't tested"); and
out-of-scope notes. Describe what the change IS, in neutral project language.
