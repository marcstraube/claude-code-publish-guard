#!/usr/bin/env python3
"""publish-guard: PreToolUse hook for the Claude Code Bash tool.

Gates every Bash command that publishes text to a remote (git commit / push,
gh pr / issue / release / api writes, glab equivalents) behind two layers:

  L2  denylist scan of the text that is about to be published (hard block,
      nothing overrides a hit)
  L1  an explicit, single-use, per-session, per-action, per-repo
      acknowledgement that Claude records with bin/publish-guard-ack after
      printing the public-content checklist

Stdlib only. Fail-closed: any internal error blocks the command (exit 2).

Entry points:
  (no args)          hook mode: reads the PreToolUse JSON from stdin
  --classify CMD     debug: print the gated actions for a command string
  --check [FILE]     scan FILE (or stdin) against the denylists, exit 1 on hit
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #

PLUGIN_ROOT = Path(
    os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent
)
DATA_DIR = Path(
    os.environ.get("CLAUDE_PLUGIN_DATA")
    or Path.home() / ".claude" / "plugins" / "data" / "publish-guard"
)
CONFIG_DIR = Path(
    os.environ.get("CLAUDE_PLUGIN_OPTION_CONFIG_DIR")
    or Path.home() / ".config" / "claude-code-publish-guard"
).expanduser()
TTL_SECONDS = int(os.environ.get("PUBLISH_GUARD_TTL", "600"))
AUDIT_MAX_BYTES = 1024 * 1024  # rotate audit.log -> audit.log.1 beyond this size
SUBPROCESS_TIMEOUT = 20
MAX_FILE_BYTES = 1_000_000

BUILTIN_PATTERNS = PLUGIN_ROOT / "patterns" / "builtin.txt"
DENYLIST_TEMPLATE = PLUGIN_ROOT / "templates" / "denylist.example.txt"
CHECKLIST_FILE = PLUGIN_ROOT / "skills" / "publish-guard" / "checklist.md"
ACK_BIN = PLUGIN_ROOT / "bin" / "publish-guard-ack"

ACTIONS = (
    "commit",
    "push",
    "pr-create",
    "pr-merge",
    "pr-edit",
    "pr-comment",
    "pr-review",
    "pr-close",
    "issue-create",
    "issue-edit",
    "issue-comment",
    "issue-close",
    "release",
    "api",
    "repo-edit",
    "gist",
)


class GuardError(Exception):
    """Anything that must block the command with an explanation."""


# --------------------------------------------------------------------------- #
# Shell scanning                                                              #
# --------------------------------------------------------------------------- #


@dataclass
class Word:
    value: str
    unresolved: bool = False  # contains $VAR / unresolved $(...) / backticks


@dataclass
class SimpleCommand:
    words: list[Word] = field(default_factory=list)
    heredoc: str | None = None
    herestring: str | None = None
    stdin_file: str | None = None
    pipe_from: "SimpleCommand | None" = None
    cwd: str = ""

    @property
    def argv(self) -> list[str]:
        return [w.value for w in self.words]


class ShellScanner:
    """Splits a Bash command string into simple commands.

    Good enough for the shapes Claude produces: quoting, escapes, heredocs,
    here-strings, pipes, `;`/`&&`/`||`, subshells, `$(...)` and backticks.
    Command substitutions are parsed recursively; their commands are added to
    the result so that `$(git commit ...)` is gated too, and `$(cat <<'EOF'
    ... EOF)`, `$(echo ...)` and `$(printf ...)` are emulated so the message
    text inside is visible to the scan.
    """

    def __init__(self, reader: Callable[[str], str] | None = None):
        self.read_file = reader or (lambda p: "")
        self.commands: list[SimpleCommand] = []

    # -- public ------------------------------------------------------------ #

    def scan(self, text: str) -> list[SimpleCommand]:
        self.commands = []
        self._scan_block(text)
        return self.commands

    # -- block scanner ----------------------------------------------------- #

    def _scan_block(self, text: str) -> None:
        i = 0
        n = len(text)
        cur = SimpleCommand()
        parts: list[str] = []
        unresolved = False
        in_word = False
        pending_heredocs: list[tuple[str, bool, SimpleCommand]] = []
        prev_pipe: SimpleCommand | None = None

        def end_word() -> None:
            nonlocal parts, unresolved, in_word
            if in_word:
                cur.words.append(Word("".join(parts), unresolved))
            parts = []
            unresolved = False
            in_word = False

        def end_command(pipe: bool = False) -> None:
            nonlocal cur, prev_pipe
            end_word()
            if cur.words or cur.heredoc is not None:
                cur.pipe_from = prev_pipe
                self.commands.append(cur)
                prev_pipe = cur if pipe else None
            else:
                prev_pipe = prev_pipe if pipe else None
            cur = SimpleCommand()

        while i < n:
            c = text[i]

            # -- newline: finish the command, then consume heredoc bodies -- #
            if c == "\n":
                end_command()
                i += 1
                if pending_heredocs:
                    for delim, strip_tabs, target in pending_heredocs:
                        body, i = self._read_heredoc_body(text, i, delim, strip_tabs)
                        target.heredoc = (target.heredoc or "") + body
                    pending_heredocs = []
                continue

            if c in " \t":
                end_word()
                i += 1
                continue

            if c == "#" and not in_word:
                while i < n and text[i] != "\n":
                    i += 1
                continue

            if c == "\\":
                if i + 1 < n and text[i + 1] == "\n":
                    i += 2
                    continue
                if i + 1 < n:
                    parts.append(text[i + 1])
                    in_word = True
                    i += 2
                else:
                    i += 1
                continue

            if c == "'":
                j = text.find("'", i + 1)
                if j < 0:
                    raise GuardError("unbalanced single quote")
                parts.append(text[i + 1 : j])
                in_word = True
                i = j + 1
                continue

            if c == '"':
                val, unres, i = self._read_dquote(text, i + 1)
                parts.append(val)
                unresolved = unresolved or unres
                in_word = True
                continue

            if c == "`":
                j = text.find("`", i + 1)
                if j < 0:
                    raise GuardError("unbalanced backtick")
                val, unres = self._substitute(text[i + 1 : j])
                parts.append(val)
                unresolved = unresolved or unres
                in_word = True
                i = j + 1
                continue

            if c == "$":
                if text.startswith("$(", i):
                    end = self._cmdsubst_end(text, i + 2)
                    val, unres = self._substitute(text[i + 2 : end])
                    parts.append(val)
                    unresolved = unresolved or unres
                    in_word = True
                    i = end + 1
                    continue
                # $VAR, ${VAR}, $1, $? ... -> keep literal, mark unresolved
                m = re.match(r"\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])", text[i:])
                if m:
                    parts.append(m.group(0))
                    unresolved = True
                    in_word = True
                    i += len(m.group(0))
                    continue
                parts.append("$")
                in_word = True
                i += 1
                continue

            # -- operators ------------------------------------------------- #
            if c == ";":
                end_command()
                i += 1
                continue
            if c == "&":
                if text.startswith("&&", i):
                    end_command()
                    i += 2
                    continue
                if text.startswith("&>", i):
                    i = self._skip_redirect_target(text, i + 2)
                    continue
                end_command()
                i += 1
                continue
            if c == "|":
                if text.startswith("||", i):
                    end_command()
                    i += 2
                    continue
                if text.startswith("|&", i):
                    end_command(pipe=True)
                    i += 2
                    continue
                end_command(pipe=True)
                i += 1
                continue
            if c in "(){}" and not in_word:
                end_command()
                i += 1
                continue

            if c == "<":
                if text.startswith("<<<", i):
                    end_word()
                    tgt, unres, i = self._read_word(text, self._skip_ws(text, i + 3))
                    cur.herestring = tgt
                    continue
                if text.startswith("<<", i):
                    end_word()
                    i += 2
                    strip_tabs = False
                    if i < n and text[i] == "-":
                        strip_tabs = True
                        i += 1
                    while i < n and text[i] in " \t":
                        i += 1
                    delim, _unres, i = self._read_word(text, i)
                    pending_heredocs.append((delim, strip_tabs, cur))
                    continue
                # plain `<` : stdin from file
                if in_word and "".join(parts).isdigit():
                    parts, in_word, unresolved = [], False, False
                else:
                    end_word()
                i += 1
                if i < n and text[i] == "&":
                    i = self._skip_redirect_target(text, i + 1)
                    continue
                tgt, _unres, i = self._read_word(text, self._skip_ws(text, i))
                cur.stdin_file = tgt
                continue

            if c == ">":
                if in_word and "".join(parts).isdigit():
                    parts, in_word, unresolved = [], False, False
                else:
                    end_word()
                i += 1
                if i < n and text[i] == ">":
                    i += 1
                if i < n and text[i] == "&":
                    i += 1
                i = self._skip_redirect_target(text, i)
                continue

            parts.append(c)
            in_word = True
            i += 1

        end_command()
        if pending_heredocs:
            # heredoc operator without a body (end of input): treat as empty
            for _delim, _st, target in pending_heredocs:
                target.heredoc = target.heredoc or ""
                if target not in self.commands and target.words:
                    self.commands.append(target)

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _skip_ws(text: str, i: int) -> int:
        while i < len(text) and text[i] in " \t":
            i += 1
        return i

    def _skip_redirect_target(self, text: str, i: int) -> int:
        i = self._skip_ws(text, i)
        _tgt, _unres, i = self._read_word(text, i)
        return i

    def _read_word(self, text: str, i: int) -> tuple[str, bool, int]:
        """Read one shell word starting at i (used for redirect targets and
        heredoc delimiters). Returns (value, unresolved, new_index)."""
        parts: list[str] = []
        unresolved = False
        n = len(text)
        while i < n and text[i] not in " \t\n;&|<>()":
            c = text[i]
            if c == "\\" and i + 1 < n:
                parts.append(text[i + 1])
                i += 2
            elif c == "'":
                j = text.find("'", i + 1)
                if j < 0:
                    raise GuardError("unbalanced single quote")
                parts.append(text[i + 1 : j])
                i = j + 1
            elif c == '"':
                val, unres, i = self._read_dquote(text, i + 1)
                parts.append(val)
                unresolved = unresolved or unres
            elif c == "$":
                if text.startswith("$(", i):
                    end = self._cmdsubst_end(text, i + 2)
                    val, unres = self._substitute(text[i + 2 : end])
                    parts.append(val)
                    unresolved = unresolved or unres
                    i = end + 1
                else:
                    m = re.match(r"\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])", text[i:])
                    if m:
                        parts.append(m.group(0))
                        unresolved = True
                        i += len(m.group(0))
                    else:
                        parts.append("$")
                        i += 1
            else:
                parts.append(c)
                i += 1
        return "".join(parts), unresolved, i

    def _read_dquote(self, text: str, i: int) -> tuple[str, bool, int]:
        parts: list[str] = []
        unresolved = False
        n = len(text)
        while i < n:
            c = text[i]
            if c == '"':
                return "".join(parts), unresolved, i + 1
            if c == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt in '"\\$`':
                    parts.append(nxt)
                    i += 2
                elif nxt == "\n":
                    i += 2
                else:
                    parts.append(c)
                    i += 1
                continue
            if c == "$" and text.startswith("$(", i):
                end = self._cmdsubst_end(text, i + 2)
                val, unres = self._substitute(text[i + 2 : end])
                parts.append(val)
                unresolved = unresolved or unres
                i = end + 1
                continue
            if c == "$":
                m = re.match(r"\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])", text[i:])
                if m:
                    parts.append(m.group(0))
                    unresolved = True
                    i += len(m.group(0))
                    continue
            if c == "`":
                j = text.find("`", i + 1)
                if j < 0:
                    raise GuardError("unbalanced backtick")
                val, unres = self._substitute(text[i + 1 : j])
                parts.append(val)
                unresolved = unresolved or unres
                i = j + 1
                continue
            parts.append(c)
            i += 1
        raise GuardError("unbalanced double quote")

    def _cmdsubst_end(self, text: str, i: int) -> int:
        """Index of the `)` closing a `$(` whose body starts at i."""
        depth = 1
        n = len(text)
        at_word_start = True
        while i < n:
            c = text[i]
            if c == "\\":
                i += 2
                continue
            if c == "'":
                j = text.find("'", i + 1)
                if j < 0:
                    raise GuardError("unbalanced single quote")
                i = j + 1
                at_word_start = False
                continue
            if c == '"':
                _v, _u, i = self._read_dquote(text, i + 1)
                at_word_start = False
                continue
            if c == "`":
                j = text.find("`", i + 1)
                if j < 0:
                    raise GuardError("unbalanced backtick")
                i = j + 1
                continue
            if c == "#" and at_word_start:
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if text.startswith("<<", i) and not text.startswith("<<<", i):
                i += 2
                strip_tabs = False
                if i < n and text[i] == "-":
                    strip_tabs = True
                    i += 1
                i = self._skip_ws(text, i)
                delim, _u, i = self._read_word(text, i)
                nl = text.find("\n", i)
                if nl < 0:
                    raise GuardError("heredoc without body inside $(...)")
                _body, i = self._read_heredoc_body(text, nl + 1, delim, strip_tabs)
                at_word_start = True
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i
            at_word_start = c in " \t\n;|&("
            i += 1
        raise GuardError("unbalanced $( ... )")

    @staticmethod
    def _read_heredoc_body(
        text: str, i: int, delim: str, strip_tabs: bool
    ) -> tuple[str, int]:
        lines: list[str] = []
        n = len(text)
        while i <= n:
            nl = text.find("\n", i)
            line = text[i:] if nl < 0 else text[i:nl]
            check = line.lstrip("\t") if strip_tabs else line
            if check == delim:
                return "\n".join(lines) + ("\n" if lines else ""), (n if nl < 0 else nl + 1)
            lines.append(check if strip_tabs else line)
            if nl < 0:
                break
            i = nl + 1
        # unterminated heredoc: bash would complain; take what we have
        return "\n".join(lines) + ("\n" if lines else ""), n

    def _substitute(self, inner: str) -> tuple[str, bool]:
        """Parse a command substitution body. Its commands join the global
        list; the return value is the emulated stdout (or a placeholder)."""
        sub = ShellScanner(self.read_file)
        cmds = sub.scan(inner)
        self.commands.extend(cmds)
        if len(cmds) == 1:
            cmd = cmds[0]
            argv = cmd.argv
            name = os.path.basename(argv[0]).lstrip("\\") if argv else ""
            if name == "cat":
                files = [a for a in argv[1:] if not a.startswith("-") or a == "-"]
                if cmd.heredoc is not None and (not files or files == ["-"]):
                    return cmd.heredoc, any(w.unresolved for w in cmd.words)
                if cmd.herestring is not None and not files:
                    return cmd.herestring + "\n", False
                if files and all(f != "-" for f in files):
                    try:
                        return "".join(self.read_file(f) for f in files), False
                    except OSError:
                        return "$(cat ...)", True
            if name == "echo":
                args = [a for a in argv[1:] if not re.fullmatch(r"-[neE]+", a)]
                return " ".join(args) + "\n", any(w.unresolved for w in cmd.words)
            if name == "printf":
                return " ".join(argv[1:]) + "\n", any(w.unresolved for w in cmd.words)
        return "$(...)", True


# --------------------------------------------------------------------------- #
# Classification                                                              #
# --------------------------------------------------------------------------- #


@dataclass
class Gated:
    action: str
    argv: list[str]  # starting at the tool name (git / gh / glab)
    cmd: SimpleCommand
    cwd: str
    repo_hint: str | None = None  # -R owner/repo for gh / glab
    git_dir: str | None = None  # -C dir for git
    unresolved: bool = False  # any word in argv carried an unresolved expansion
    extra_note: str | None = None


GIT_GLOBAL_WITH_ARG = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--config-env",
    "--super-prefix",
    "--list-cmds",
    "--attr-source",
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
INTERPRETERS = {"python", "python3", "python2", "perl", "node", "ruby", "php"}
WRAPPER_VALUE_OPTS = {
    "command": set(),
    "builtin": set(),
    "exec": set(),
    "nohup": set(),
    "time": set(),
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "sudo": {"-u", "--user", "-g", "--group", "-C", "-D", "-h", "--host", "-p", "-r", "-t", "-U"},
    "doas": {"-u", "-C"},
    "xargs": {"-I", "-n", "-P", "-d", "-a", "-L", "-s", "-E", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
    "stdbuf": {"-i", "-o", "-e"},
    "caffeinate": set(),
}

GH_TABLE: dict[tuple[str, str], str] = {
    ("pr", "create"): "pr-create",
    ("pr", "merge"): "pr-merge",
    ("pr", "edit"): "pr-edit",
    ("pr", "comment"): "pr-comment",
    ("pr", "review"): "pr-review",
    ("pr", "close"): "pr-close",
    ("pr", "reopen"): "pr-close",
    ("issue", "create"): "issue-create",
    ("issue", "edit"): "issue-edit",
    ("issue", "comment"): "issue-comment",
    ("issue", "close"): "issue-close",
    ("issue", "reopen"): "issue-close",
    ("release", "create"): "release",
    ("release", "edit"): "release",
    ("repo", "edit"): "repo-edit",
    ("repo", "create"): "repo-edit",
    ("repo", "rename"): "repo-edit",
    ("gist", "create"): "gist",
    ("gist", "edit"): "gist",
    ("discussion", "create"): "issue-create",
    ("discussion", "comment"): "issue-comment",
}
GLAB_TABLE: dict[tuple[str, str], str] = {
    ("mr", "create"): "pr-create",
    ("mr", "merge"): "pr-merge",
    ("mr", "update"): "pr-edit",
    ("mr", "note"): "pr-comment",
    ("mr", "close"): "pr-close",
    ("mr", "reopen"): "pr-close",
    ("mr", "approve"): "pr-review",
    ("issue", "create"): "issue-create",
    ("issue", "update"): "issue-edit",
    ("issue", "note"): "issue-comment",
    ("issue", "close"): "issue-close",
    ("issue", "reopen"): "issue-close",
    ("release", "create"): "release",
    ("release", "update"): "release",
    ("repo", "create"): "repo-edit",
    ("repo", "update"): "repo-edit",
    ("api", "api"): "api",
}


class Classifier:
    def __init__(self, scanner_factory: Callable[[], ShellScanner], base_cwd: str):
        self.scanner_factory = scanner_factory
        self.base_cwd = base_cwd

    def classify_text(self, text: str, cwd: str | None = None) -> list[Gated]:
        scanner = self.scanner_factory()
        commands = scanner.scan(text)
        return self._classify_commands(commands, cwd or self.base_cwd)

    def _classify_commands(self, commands: list[SimpleCommand], cwd: str) -> list[Gated]:
        gated: list[Gated] = []
        for cmd in commands:
            cmd.cwd = cwd
            argv = cmd.argv
            if not argv:
                continue
            words = self._strip_wrappers(cmd.words)
            if not words:
                continue
            name = os.path.basename(words[0].value).lstrip("\\")
            rest = words[1:]

            if name in ("cd", "pushd"):
                target = next((w.value for w in rest if not w.value.startswith("-")), None)
                if target is None or target == "~":
                    cwd = str(Path.home())
                elif target != "-" and not any(w.unresolved for w in rest):
                    cwd = os.path.normpath(os.path.join(cwd, os.path.expanduser(target)))
                continue

            if name == "git":
                g = self._classify_git(words, cmd, cwd)
                if g:
                    gated.append(g)
                continue
            if name == "gh":
                gated.extend(self._classify_gh(words, cmd, cwd, GH_TABLE, "gh"))
                continue
            if name == "glab":
                gated.extend(self._classify_gh(words, cmd, cwd, GLAB_TABLE, "glab"))
                continue
            if name in SHELLS:
                gated.extend(self._classify_shell(words, cmd, cwd))
                continue
            if name == "eval":
                inner = " ".join(w.value for w in rest)
                gated.extend(self.classify_text(inner, cwd))
                continue
            if name in INTERPRETERS:
                self._check_inline_interpreter(name, words, cmd)
                continue
        return gated

    # -- wrappers ---------------------------------------------------------- #

    @staticmethod
    def _strip_wrappers(words: list[Word]) -> list[Word]:
        i = 0
        n = len(words)
        while i < n:
            v = words[i].value
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", v, re.S):
                i += 1
                continue
            name = os.path.basename(v).lstrip("\\")
            if name not in WRAPPER_VALUE_OPTS:
                break
            value_opts = WRAPPER_VALUE_OPTS[name]
            i += 1
            positional_to_skip = 1 if name == "timeout" else 0
            while i < n:
                v = words[i].value
                if v == "--":
                    i += 1
                    break
                if v.startswith("-") and len(v) > 1:
                    opt = v.split("=", 1)[0]
                    if opt in value_opts and "=" not in v:
                        i += 2
                    else:
                        i += 1
                    continue
                if name in ("env", "sudo", "doas") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", v, re.S):
                    i += 1
                    continue
                if positional_to_skip:
                    positional_to_skip -= 1
                    i += 1
                    continue
                break
        return words[i:]

    # -- git --------------------------------------------------------------- #

    def _classify_git(self, words: list[Word], cmd: SimpleCommand, cwd: str) -> Gated | None:
        argv = [w.value for w in words]
        unresolved_any = any(w.unresolved for w in words)
        i = 1
        git_dir: str | None = None
        git_dir_unresolved = False
        n = len(argv)
        while i < n:
            a = argv[i]
            if not a.startswith("-"):
                break
            if a in ("--help", "-h", "--version"):
                return None
            opt, eq, val = a.partition("=")
            if opt in GIT_GLOBAL_WITH_ARG:
                if eq:
                    value = val
                    consumed = 1
                elif len(a) > 2 and opt in ("-C", "-c") and a[:2] == opt:
                    value = a[2:]
                    opt = a[:2]
                    consumed = 1
                else:
                    value = argv[i + 1] if i + 1 < n else ""
                    consumed = 2
                if opt == "-C":
                    if words[i + consumed - 1].unresolved:
                        git_dir_unresolved = True
                    git_dir = os.path.normpath(os.path.join(git_dir or cwd, os.path.expanduser(value)))
                elif opt == "--work-tree":
                    git_dir = os.path.normpath(os.path.join(cwd, os.path.expanduser(value)))
                i += consumed
                continue
            if len(a) > 2 and a[:2] in ("-C", "-c") and not a.startswith("--"):
                value = a[2:]
                if a[:2] == "-C":
                    git_dir = os.path.normpath(os.path.join(git_dir or cwd, os.path.expanduser(value)))
                i += 1
                continue
            i += 1
        if i >= n:
            return None
        sub = argv[i]
        if sub not in ("commit", "push"):
            return None
        if any(x in ("--help", "-h") for x in argv[i + 1 :]):
            return None
        g = Gated(
            action=sub,
            argv=argv[i:],
            cmd=cmd,
            cwd=cwd,
            git_dir=git_dir,
            unresolved=unresolved_any,
        )
        if git_dir_unresolved:
            raise GuardError(
                "git -C <dir> uses a shell variable; publish-guard cannot tell which "
                "repository this targets. Write the path literally."
            )
        return g

    # -- gh / glab --------------------------------------------------------- #

    def _classify_gh(
        self,
        words: list[Word],
        cmd: SimpleCommand,
        cwd: str,
        table: dict[tuple[str, str], str],
        tool: str,
    ) -> list[Gated]:
        argv = [w.value for w in words]
        if any(a in ("--help", "-h", "--version") for a in argv):
            return []
        repo_hint: str | None = None
        positionals: list[int] = []
        i = 1
        n = len(argv)
        while i < n:
            a = argv[i]
            if a in ("-R", "--repo"):
                repo_hint = argv[i + 1] if i + 1 < n else None
                i += 2
                continue
            if a.startswith("--repo="):
                repo_hint = a.split("=", 1)[1]
                i += 1
                continue
            if a.startswith("-R") and len(a) > 2:
                repo_hint = a[2:]
                i += 1
                continue
            if not a.startswith("-") and len(positionals) < 2:
                positionals.append(i)
            i += 1
        if not positionals:
            return []
        noun = argv[positionals[0]]
        verb = argv[positionals[1]] if len(positionals) > 1 else None

        unresolved_any = any(w.unresolved for w in words)
        gated: list[Gated] = []

        if noun == "api":
            if self._gh_api_is_write(argv[positionals[0] + 1 :]):
                gated.append(
                    Gated("api", argv[positionals[0] :], cmd, cwd, repo_hint=repo_hint, unresolved=unresolved_any)
                )
            return gated

        if verb is None:
            return []
        action = table.get((noun, verb))
        if action is None:
            return []
        gated.append(
            Gated(action, argv[positionals[0] :], cmd, cwd, repo_hint=repo_hint, unresolved=unresolved_any)
        )
        if action == "pr-create" and tool == "gh":
            # gh pr create pushes the branch when it is not on the remote yet
            push = Gated("push", ["push"], cmd, cwd, repo_hint=repo_hint, unresolved=False)
            push.extra_note = "implicit push by gh pr create"
            gated.append(push)
        return gated

    @staticmethod
    def _gh_api_is_write(args: list[str]) -> bool:
        method = "GET"
        has_fields = False
        i = 0
        n = len(args)
        while i < n:
            a = args[i]
            if a in ("-X", "--method"):
                method = (args[i + 1] if i + 1 < n else "GET").upper()
                i += 2
                continue
            if a.startswith("--method="):
                method = a.split("=", 1)[1].upper()
            elif a.startswith("-X") and len(a) > 2:
                method = a[2:].upper()
            elif a in ("-f", "-F", "--field", "--raw-field", "--input") or a.startswith(
                ("--field=", "--raw-field=", "--input=")
            ):
                has_fields = True
            elif a == "graphql":
                pass
            i += 1
        if method != "GET":
            return True
        if has_fields:
            # fields switch gh to POST, except an explicit GET with query fields
            # (gh api graphql always POSTs; a `query` is read-only only if it
            # contains no mutation, which we check in extraction)
            return True
        return False

    # -- shells and interpreters ------------------------------------------ #

    def _classify_shell(self, words: list[Word], cmd: SimpleCommand, cwd: str) -> list[Gated]:
        argv = [w.value for w in words]
        for i, a in enumerate(argv[1:], start=1):
            if a in ("-c", "-lc", "-ec", "-euc", "-exc", "-ic") or (
                a.startswith("-") and not a.startswith("--") and "c" in a[1:]
            ):
                if i + 1 < len(argv):
                    if words[i + 1].unresolved:
                        raise GuardError(
                            "shell -c receives a string built from variables; publish-guard "
                            "cannot inspect it. Run the git/gh command directly."
                        )
                    return self.classify_text(argv[i + 1], cwd)
                return []
            if not a.startswith("-"):
                break  # script file argument: not inspectable, not gated
        if cmd.heredoc is not None:
            return self.classify_text(cmd.heredoc, cwd)
        if cmd.pipe_from is not None:
            producer = cmd.pipe_from
            if producer.heredoc is not None:
                return self.classify_text(producer.heredoc, cwd)
            raise GuardError(
                "a shell reads its script from a pipe; publish-guard cannot inspect it. "
                "Run the git/gh command directly."
            )
        return []

    @staticmethod
    def _check_inline_interpreter(name: str, words: list[Word], cmd: SimpleCommand) -> None:
        argv = [w.value for w in words]
        code = ""
        for i, a in enumerate(argv[1:], start=1):
            if a in ("-c", "-e", "-E", "-r"):
                code = argv[i + 1] if i + 1 < len(argv) else ""
                break
            if a == "-" and cmd.heredoc is not None:
                code = cmd.heredoc
                break
        if not code and cmd.heredoc is not None and all(a.startswith("-") for a in argv[1:]):
            code = cmd.heredoc
        if code and re.search(r"\b(git|gh|glab)\b", code):
            raise GuardError(
                f"inline {name} code mentions git/gh; publish-guard cannot inspect what it "
                "publishes. Run the git/gh command directly in Bash."
            )


# --------------------------------------------------------------------------- #
# Runner (git / gh invocations, mockable in tests)                            #
# --------------------------------------------------------------------------- #


class Runner:
    def run(self, argv: list[str], cwd: str | None = None) -> tuple[int, str, str]:
        try:
            p = subprocess.run(
                argv,
                cwd=cwd if cwd and os.path.isdir(cwd) else None,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GH_PROMPT_DISABLED": "1", "GH_PAGER": "cat", "PAGER": "cat"},
            )
        except FileNotFoundError:
            return 127, "", f"{argv[0]}: not found"
        except subprocess.TimeoutExpired:
            return 124, "", f"{' '.join(argv[:3])}: timed out"
        return p.returncode, p.stdout, p.stderr

    def git(self, cwd: str, *args: str) -> str:
        rc, out, err = self.run(["git", *args], cwd=cwd)
        if rc != 0:
            raise GuardError(f"git {' '.join(args[:2])} failed in {cwd}: {err.strip() or rc}")
        return out

    def git_ok(self, cwd: str, *args: str) -> str | None:
        rc, out, _err = self.run(["git", *args], cwd=cwd)
        return out if rc == 0 else None

    def gh(self, cwd: str, *args: str) -> str:
        rc, out, err = self.run(["gh", *args], cwd=cwd)
        if rc != 0:
            raise GuardError(f"gh {' '.join(args[:2])} failed: {err.strip() or rc}")
        return out


# --------------------------------------------------------------------------- #
# Text extraction                                                             #
# --------------------------------------------------------------------------- #


@dataclass
class TextSource:
    label: str
    text: str


TRAILER_RE = re.compile(r"^(Signed-off-by|Co-authored-by):", re.I)


class Extractor:
    def __init__(self, runner: Runner, read_file: Callable[[str], str]):
        self.runner = runner
        self.read_file = read_file

    # -- helpers ----------------------------------------------------------- #

    def _stdin_text(self, g: Gated, what: str) -> str:
        cmd = g.cmd
        if cmd.heredoc is not None:
            return cmd.heredoc
        if cmd.herestring is not None:
            return cmd.herestring + "\n"
        if cmd.stdin_file:
            return self._read(cmd.stdin_file, g.effective_dir if hasattr(g, "effective_dir") else g.cwd)
        prod = cmd.pipe_from
        if prod is not None:
            argv = prod.argv
            name = os.path.basename(argv[0]).lstrip("\\") if argv else ""
            if name == "cat":
                if prod.heredoc is not None:
                    return prod.heredoc
                files = [a for a in argv[1:] if not a.startswith("-")]
                if files:
                    return "".join(self._read(f, g.cwd) for f in files)
            if name == "echo":
                return " ".join(a for a in argv[1:] if not re.fullmatch(r"-[neE]+", a)) + "\n"
            if name == "printf":
                return " ".join(argv[1:]) + "\n"
        raise GuardError(
            f"{what} is read from stdin but publish-guard cannot see that text. "
            "Use a heredoc, a here-string, or a literal -m/--body argument."
        )

    def _read(self, path: str, cwd: str) -> str:
        p = Path(os.path.expanduser(path))
        if not p.is_absolute():
            p = Path(cwd) / p
        try:
            return self.read_file(str(p))
        except OSError as e:
            raise GuardError(f"cannot read {p}: {e.strerror or e}") from e

    @staticmethod
    def _check_unresolved(g: Gated, values: list[tuple[str, bool]]) -> None:
        bad = [v for v, u in values if u]
        if bad:
            raise GuardError(
                "the text to be published contains a shell variable or an unresolved "
                f"command substitution ({bad[0][:60]!r}); publish-guard can only check "
                "literal text. Write the message literally (heredoc or -m)."
            )

    def _repo_dir(self, g: Gated) -> str:
        return g.git_dir or g.cwd

    # -- dispatcher -------------------------------------------------------- #

    def extract(self, g: Gated) -> list[TextSource]:
        if g.action == "commit":
            return self._commit(g)
        if g.action == "push":
            return self._push(g)
        if g.action == "pr-create":
            return self._pr_create(g)
        if g.action == "pr-merge":
            return self._pr_merge(g)
        if g.action == "release":
            return self._release(g)
        if g.action == "api":
            return self._api(g)
        if g.action == "gist":
            return self._gist(g)
        return self._generic(g)

    # -- git commit -------------------------------------------------------- #

    def _commit(self, g: Gated) -> list[TextSource]:
        words = self._words_after(g, 1)
        out: list[TextSource] = []
        messages: list[tuple[str, bool]] = []
        reuse: str | None = None
        amend = False
        has_message = False
        i = 0
        n = len(words)
        repo = self._repo_dir(g)
        while i < n:
            w = words[i]
            a = w.value
            nxt = words[i + 1] if i + 1 < n else None

            def take(flag_len: int) -> tuple[str, bool]:
                nonlocal i
                if len(a) > flag_len:
                    return a[flag_len:], w.unresolved
                i += 1
                return (nxt.value, nxt.unresolved) if nxt else ("", False)

            if a == "--":
                break
            if a.startswith("--message="):
                messages.append((a.split("=", 1)[1], w.unresolved))
                has_message = True
            elif a == "--message":
                messages.append(take(len(a)))
                has_message = True
            elif a.startswith("-m") and not a.startswith("--"):
                messages.append(take(2))
                has_message = True
            elif a.startswith("--file="):
                messages.append(self._msg_file(g, a.split("=", 1)[1], repo))
                has_message = True
            elif a == "--file":
                val, _u = take(len(a))
                messages.append(self._msg_file(g, val, repo))
                has_message = True
            elif a.startswith("-F") and not a.startswith("--"):
                val, _u = take(2)
                messages.append(self._msg_file(g, val, repo))
                has_message = True
            elif a.startswith(("--reuse-message=", "--reedit-message=")):
                reuse = a.split("=", 1)[1]
            elif a in ("--reuse-message", "--reedit-message"):
                reuse, _u = take(len(a))
            elif a.startswith(("-C", "-c")) and not a.startswith("--"):
                reuse, _u = take(2)
            elif a.startswith("--squash="):
                reuse = a.split("=", 1)[1]
                messages.append(("squash! ", False))
            elif a.startswith("--fixup="):
                reuse = a.split("=", 1)[1].split(":", 1)[-1]
                messages.append(("fixup! ", False))
            elif a in ("--squash", "--fixup"):
                reuse, _u = take(len(a))
            elif a == "--amend":
                amend = True
            elif a.startswith("--trailer="):
                messages.append((a.split("=", 1)[1], w.unresolved))
            elif a == "--trailer":
                messages.append(take(len(a)))
            elif a.startswith("--template="):
                messages.append(self._msg_file(g, a.split("=", 1)[1], repo))
            elif a in ("-t", "--template"):
                val, _u = take(len(a))
                messages.append(self._msg_file(g, val, repo))
            elif a in ("-e", "--edit", "--no-edit", "-a", "--all", "-s", "--signoff", "-S",
                       "--gpg-sign", "--no-gpg-sign", "-n", "--no-verify", "-q", "--quiet",
                       "-v", "--verbose", "--allow-empty", "--allow-empty-message", "-i",
                       "--include", "-o", "--only", "--dry-run", "--status", "--no-status",
                       "-z", "--null", "--branch", "--long", "--short", "--porcelain",
                       "--reset-author", "-p", "--patch", "--interactive", "--no-post-rewrite"):
                pass
            elif a.startswith("-S") and len(a) > 2:
                pass  # -S<keyid>
            elif a in ("--author", "--date", "--cleanup", "--untracked-files", "-u", "--pathspec-from-file", "--fixup"):
                i += 1
            i += 1

        self._check_unresolved(g, messages)
        for m, _u in messages:
            out.append(TextSource("commit message", m))
        if reuse:
            out.append(TextSource(f"reused message ({reuse})", self.runner.git(repo, "log", "-1", "--format=%B", reuse)))
        elif amend and not has_message:
            out.append(TextSource("amended HEAD message", self.runner.git(repo, "log", "-1", "--format=%B", "HEAD")))
        return out

    def _msg_file(self, g: Gated, path: str, repo: str) -> tuple[str, bool]:
        if path == "-":
            return self._stdin_text(g, "the commit message (-F -)"), False
        return self._read(path, repo), False

    # -- git push ---------------------------------------------------------- #

    PUSH_VALUE_OPTS = {"-o", "--push-option", "--receive-pack", "--exec", "--repo", "--recurse-submodules", "--signed", "--force-with-lease", "--force-if-includes"}

    def _push(self, g: Gated) -> list[TextSource]:
        repo = self._repo_dir(g)
        words = self._words_after(g, 1)
        out: list[TextSource] = []
        positionals: list[str] = []
        flags: set[str] = set()
        i = 0
        n = len(words)
        while i < n:
            a = words[i].value
            if a == "--":
                positionals.extend(w.value for w in words[i + 1 :])
                break
            if a.startswith("-"):
                opt = a.split("=", 1)[0]
                if opt in ("-o", "--push-option"):
                    val = a.split("=", 1)[1] if "=" in a else (words[i + 1].value if i + 1 < n else "")
                    out.append(TextSource("push option", val))
                if opt in self.PUSH_VALUE_OPTS and "=" not in a and opt not in ("--force-with-lease", "--force-if-includes", "--signed", "--recurse-submodules"):
                    i += 2
                    continue
                flags.add(opt)
                i += 1
                continue
            positionals.append(a)
            i += 1

        if not self.runner.git_ok(repo, "rev-parse", "--git-dir"):
            raise GuardError(f"{repo} is not a git repository; cannot inspect what would be pushed")

        remote = positionals[0] if positionals else self._default_remote(repo)
        refspecs = positionals[1:]
        for r in refspecs:
            out.append(TextSource("refspec", r))

        all_refs = bool(flags & {"--all", "--mirror", "--branches"})
        if "--delete" in flags or "-d" in flags:
            return out  # deleting refs publishes nothing new

        srcs: list[str] = []
        tag_names: list[str] = []
        for r in refspecs:
            src = r.lstrip("+").split(":", 1)[0]
            if not src:
                continue
            if src.startswith("refs/tags/"):
                tag_names.append(src[len("refs/tags/") :])
            elif self.runner.git_ok(repo, "show-ref", "--verify", "--quiet", f"refs/tags/{src}") is not None:
                tag_names.append(src)
            else:
                srcs.append(src)
        if not refspecs:
            srcs = ["HEAD"]

        rev_args = ["rev-list", "--format=%B%x00"]
        if all_refs:
            rev_args += ["--branches"]
        else:
            rev_args += srcs
        rev_args += ["--not", f"--remotes={remote}"]
        listing = self.runner.git_ok(repo, *rev_args)
        if listing is None:
            # remote unknown or ref invalid: fall back to everything not on any remote
            listing = self.runner.git(repo, "rev-list", "--format=%B%x00", "--branches", "--not", "--remotes")
        for chunk in listing.split("\x00"):
            chunk = chunk.strip()
            if not chunk:
                continue
            lines = chunk.split("\n", 1)
            sha = lines[0].replace("commit ", "")[:12]
            body = lines[1] if len(lines) > 1 else ""
            out.append(TextSource(f"unpushed commit {sha}", body))

        if srcs and not all_refs:
            branch = self.runner.git_ok(repo, "rev-parse", "--abbrev-ref", "HEAD")
            if branch:
                out.append(TextSource("branch name", branch.strip()))

        if flags & {"--tags", "--mirror"}:
            tags = self.runner.git_ok(repo, "for-each-ref", "refs/tags", "--format=%(refname:short)%0a%(contents)%00")
            if tags:
                for chunk in tags.split("\x00"):
                    if chunk.strip():
                        out.append(TextSource("tag", chunk.strip()))
        elif "--follow-tags" in flags or tag_names:
            for t in tag_names:
                content = self.runner.git_ok(repo, "tag", "-l", "--format=%(contents)", t)
                out.append(TextSource(f"tag {t}", f"{t}\n{content or ''}"))
            if "--follow-tags" in flags:
                tags = self.runner.git_ok(repo, "for-each-ref", "refs/tags", "--format=%(refname:short)%0a%(contents)%00")
                if tags:
                    for chunk in tags.split("\x00"):
                        if chunk.strip():
                            out.append(TextSource("tag (follow-tags)", chunk.strip()))
        return out

    def _default_remote(self, repo: str) -> str:
        branch = (self.runner.git_ok(repo, "symbolic-ref", "--short", "-q", "HEAD") or "").strip()
        for key in (f"branch.{branch}.pushRemote", "remote.pushDefault", f"branch.{branch}.remote"):
            if branch or not key.startswith("branch."):
                v = self.runner.git_ok(repo, "config", "--get", key)
                if v and v.strip():
                    return v.strip()
        return "origin"

    # -- gh pr create ------------------------------------------------------ #

    def _pr_create(self, g: Gated) -> list[TextSource]:
        out = self._generic(g)
        argv = g.argv
        repo = self._repo_dir(g)
        if any(a.startswith("--fill") for a in argv):
            base = self._flag_value(argv, ("-B", "--base"))
            if not base:
                head = self.runner.git_ok(repo, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD")
                base = head.strip() if head else "origin/main"
            log = self.runner.git_ok(repo, "log", "--format=%B%x00", f"{base}..HEAD")
            if log is None:
                log = self.runner.git(repo, "log", "--format=%B%x00", "-20")
            for chunk in log.split("\x00"):
                if chunk.strip():
                    out.append(TextSource("commit used by --fill", chunk.strip()))
        branch = self.runner.git_ok(repo, "rev-parse", "--abbrev-ref", "HEAD")
        if branch:
            out.append(TextSource("head branch name", branch.strip()))
        return out

    # -- gh pr merge ------------------------------------------------------- #

    MERGE_VALUE_OPTS = {"-t", "--subject", "-b", "--body", "-F", "--body-file", "-A", "--author-email", "--match-head-commit", "-R", "--repo"}

    def _pr_merge(self, g: Gated) -> list[TextSource]:
        out = self._generic(g)
        argv = g.argv
        if argv and argv[0] == "api":
            return out
        if os.path.basename(g.cmd.argv[0]) == "glab" or (g.argv and g.argv[0] == "mr"):
            return out  # glab: no live fetch implemented; ack still required
        selector = None
        i = 2
        while i < len(argv):
            a = argv[i]
            if a.startswith("-"):
                if a.split("=", 1)[0] in self.MERGE_VALUE_OPTS and "=" not in a:
                    i += 2
                    continue
                i += 1
                continue
            selector = a
            break
        gh_args = ["pr", "view"]
        if selector:
            gh_args.append(selector)
        if g.repo_hint:
            gh_args += ["-R", g.repo_hint]
        gh_args += ["--json", "title,body,commits,headRefName"]
        raw = self.runner.gh(g.cwd, *gh_args)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise GuardError(f"gh pr view returned no JSON: {e}") from e
        out.append(TextSource("PR title (live)", data.get("title") or ""))
        out.append(TextSource("PR body (live)", data.get("body") or ""))
        out.append(TextSource("PR head branch", data.get("headRefName") or ""))
        for c in data.get("commits") or []:
            oid = (c.get("oid") or "")[:12]
            msg = "\n".join(x for x in (c.get("messageHeadline"), c.get("messageBody")) if x)
            out.append(TextSource(f"PR commit {oid}", msg))
        return out

    # -- gh release -------------------------------------------------------- #

    def _release(self, g: Gated) -> list[TextSource]:
        out = self._generic(g)
        argv = g.argv
        repo = self._repo_dir(g)
        tag = next((a for a in argv[2:] if not a.startswith("-")), None)
        if "--notes-from-tag" in argv and tag:
            content = self.runner.git_ok(repo, "tag", "-l", "--format=%(contents)", tag)
            out.append(TextSource(f"tag message {tag}", content or ""))
        if "--generate-notes" in argv and tag:
            prev = self.runner.git_ok(repo, "describe", "--tags", "--abbrev=0", f"{tag}^") if self.runner.git_ok(repo, "rev-parse", "-q", "--verify", f"{tag}^{{commit}}") else None
            rng = f"{prev.strip()}..{tag}" if prev and prev.strip() else "-50"
            log = self.runner.git_ok(repo, "log", "--format=%B%x00", rng) or self.runner.git_ok(repo, "log", "--format=%B%x00", "-50") or ""
            for chunk in log.split("\x00"):
                if chunk.strip():
                    out.append(TextSource("commit used by --generate-notes", chunk.strip()))
        return out

    # -- gh api ------------------------------------------------------------ #

    def _api(self, g: Gated) -> list[TextSource]:
        words = self._words_after(g, 1)
        out: list[TextSource] = []
        vals: list[tuple[str, bool]] = []
        i = 0
        n = len(words)
        while i < n:
            w = words[i]
            a = w.value
            if a in ("-f", "-F", "--field", "--raw-field"):
                nxt = words[i + 1] if i + 1 < n else None
                if nxt:
                    self._api_field(g, nxt.value, nxt.unresolved, vals, out)
                i += 2
                continue
            if a.startswith(("--field=", "--raw-field=")):
                self._api_field(g, a.split("=", 1)[1], w.unresolved, vals, out)
            elif a == "--input":
                nxt = words[i + 1].value if i + 1 < n else ""
                out.append(TextSource("api --input", self._stdin_text(g, "gh api --input -") if nxt == "-" else self._read(nxt, g.cwd)))
                i += 2
                continue
            elif a.startswith("--input="):
                p = a.split("=", 1)[1]
                out.append(TextSource("api --input", self._stdin_text(g, "gh api --input -") if p == "-" else self._read(p, g.cwd)))
            elif not a.startswith("-"):
                vals.append((a, w.unresolved))
            i += 1
        self._check_unresolved(g, vals)
        out.extend(TextSource("api argument", v) for v, _u in vals)
        return out

    def _api_field(self, g: Gated, kv: str, unresolved: bool, vals: list[tuple[str, bool]], out: list[TextSource]) -> None:
        key, _eq, value = kv.partition("=")
        if value.startswith("@"):
            path = value[1:]
            out.append(TextSource(f"api field {key} (file)", self._stdin_text(g, f"field {key}") if path == "-" else self._read(path, g.cwd)))
        else:
            vals.append((kv, unresolved))

    # -- gh gist ----------------------------------------------------------- #

    def _gist(self, g: Gated) -> list[TextSource]:
        out = self._generic(g)
        for a in g.argv[2:]:
            if a == "-":
                out.append(TextSource("gist stdin", self._stdin_text(g, "gist content")))
            elif not a.startswith("-") and os.path.isfile(os.path.join(g.cwd, os.path.expanduser(a))):
                out.append(TextSource(f"gist file {a}", self._read(a, g.cwd)))
        return out

    # -- generic gh / glab: every token after the verb + referenced files -- #

    FILE_FLAGS = {"-F", "--body-file", "--notes-file", "--description-file", "--file"}

    def _generic(self, g: Gated) -> list[TextSource]:
        words = self._words_after(g, 2)
        out: list[TextSource] = []
        vals: list[tuple[str, bool]] = []
        i = 0
        n = len(words)
        while i < n:
            w = words[i]
            a = w.value
            opt, eq, val = a.partition("=")
            if opt in self.FILE_FLAGS:
                if not eq:
                    val = words[i + 1].value if i + 1 < n else ""
                    i += 1
                label = f"{opt} content"
                out.append(TextSource(label, self._stdin_text(g, f"{opt} -") if val == "-" else self._read(val, g.cwd)))
            elif a == "-" and i > 0:
                out.append(TextSource("stdin", self._stdin_text(g, "stdin text")))
            else:
                vals.append((a, w.unresolved))
            i += 1
        self._check_unresolved(g, vals)
        out.append(TextSource("arguments", "\n".join(v for v, _u in vals)))
        return out

    # -- utilities --------------------------------------------------------- #

    def _words_after(self, g: Gated, skip: int) -> list[Word]:
        """Words of the original command starting after g.argv[skip-1]."""
        cmd_words = g.cmd.words
        # locate g.argv inside the command's words (after wrappers / globals)
        start = len(cmd_words) - len(g.argv)
        if start < 0 or [w.value for w in cmd_words[start:]] != g.argv:
            # implicit gated entry (e.g. push synthesized from pr create)
            return [Word(a) for a in g.argv[skip:]]
        return cmd_words[start + skip :]

    @staticmethod
    def _flag_value(argv: list[str], names: tuple[str, ...]) -> str | None:
        for i, a in enumerate(argv):
            if a in names and i + 1 < len(argv):
                return argv[i + 1]
            for nm in names:
                if a.startswith(nm + "="):
                    return a.split("=", 1)[1]
        return None


# --------------------------------------------------------------------------- #
# Denylist                                                                    #
# --------------------------------------------------------------------------- #


@dataclass
class Pattern:
    pattern_id: str
    regex: re.Pattern
    section: str  # always | messages-only


def load_patterns(path: Path, origin: str) -> list[Pattern]:
    patterns: list[Pattern] = []
    section = "always"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return patterns
    except OSError as e:
        raise GuardError(f"cannot read pattern file {path}: {e.strerror}") from e
    for no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[(always|messages-only)\]\s*(#.*)?", line)
        if m:
            section = m.group(1)
            continue
        try:
            rx = re.compile(line, re.IGNORECASE)
        except re.error as e:
            raise GuardError(f"{path}:{no}: invalid regex {line!r}: {e}") from e
        patterns.append(Pattern(f"{origin}:{no}", rx, section))
    return patterns


def ensure_private_denylist() -> Path:
    path = CONFIG_DIR / "denylist.txt"
    if path.exists():
        return path
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        template = DENYLIST_TEMPLATE.read_text(encoding="utf-8")
    except OSError:
        template = "# publish-guard private denylist: one regex per line\n[always]\n[messages-only]\n"
    path.write_text(template, encoding="utf-8")
    path.chmod(0o600)
    return path


@dataclass
class Hit:
    pattern_id: str
    source: str
    line: str


def scan_sources(sources: list[TextSource], patterns: list[Pattern]) -> list[Hit]:
    hits: list[Hit] = []
    for src in sources:
        for line in src.text.splitlines():
            if TRAILER_RE.match(line.strip()):
                continue  # author trailers carry identities that are public anyway
            for p in patterns:
                if p.regex.search(line):
                    excerpt = line.strip()
                    if len(excerpt) > 120:
                        excerpt = excerpt[:117] + "..."
                    hits.append(Hit(p.pattern_id, src.label, excerpt))
    return hits


# --------------------------------------------------------------------------- #
# Acknowledgement sentinels                                                   #
# --------------------------------------------------------------------------- #


def ack_base_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base and os.path.isdir(base):
        return Path(base) / "publish-guard"
    return Path(os.environ.get("TMPDIR") or "/tmp") / f"publish-guard-{os.getuid()}"


def repo_key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def resolve_repo_key(g: Gated, runner: Runner) -> str:
    if g.repo_hint:
        return g.repo_hint
    d = g.git_dir or g.cwd
    top = runner.git_ok(d, "rev-parse", "--show-toplevel")
    if top and top.strip():
        return os.path.realpath(top.strip())
    return os.path.realpath(d)


class AckStore:
    def __init__(self, session_id: str, base: Path | None = None):
        self.session_id = session_id or "unknown-session"
        self.dir = (base or ack_base_dir()) / self.session_id

    def path(self, action: str, repo_key: str) -> Path:
        return self.dir / f"{action}.{repo_key_hash(repo_key)}.json"

    def valid(self, action: str, repo_key: str) -> bool:
        p = self.path(action, repo_key)
        try:
            st = p.stat()
        except FileNotFoundError:
            return False
        return (time.time() - st.st_mtime) <= TTL_SECONDS

    def consume(self, action: str, repo_key: str) -> None:
        try:
            self.path(action, repo_key).unlink()
        except FileNotFoundError:
            pass

    def purge_expired(self) -> None:
        """Remove expired acks in every session directory under the base and
        drop session directories that are empty and older than the TTL, so
        finished sessions do not accumulate (the base is per-user tmpfs or
        /tmp and would otherwise only be cleared at logout, or never)."""
        now = time.time()
        try:
            session_dirs = [d for d in self.dir.parent.iterdir() if d.is_dir()]
        except FileNotFoundError:
            return
        for d in session_dirs:
            try:
                was_old = now - d.stat().st_mtime > TTL_SECONDS
                removed = False
                for p in d.iterdir():
                    try:
                        if p.suffix == ".json" and now - p.stat().st_mtime > TTL_SECONDS:
                            p.unlink()
                            removed = True
                    except FileNotFoundError:
                        pass
                # a directory the ack script just created (fresh, empty) is kept
                if (was_old or removed) and not any(d.iterdir()):
                    d.rmdir()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Decision                                                                    #
# --------------------------------------------------------------------------- #


def checklist_text() -> str:
    try:
        return CHECKLIST_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return "(checklist file missing: " + str(CHECKLIST_FILE) + ")"


def audit(session_id: str, decision: str, actions: list[str], repo_keys: list[str], command: str) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        log = DATA_DIR / "audit.log"
        try:
            if log.stat().st_size > AUDIT_MAX_BYTES:
                log.replace(log.with_suffix(".log.1"))
        except FileNotFoundError:
            pass
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cmd = command.replace("\n", "\\n")[:200]
        with log.open("a", encoding="utf-8") as fh:
            fh.write(
                f"{ts} sess={session_id[:8]} decision={decision} actions={','.join(actions) or '-'} "
                f"repos={';'.join(sorted(set(repo_keys))) or '-'} cmd={cmd!r}\n"
            )
    except OSError:
        pass


def deny(reason: str, system_message: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                },
                "systemMessage": system_message,
            }
        )
    )


def format_noack(missing: list[tuple[str, str]], gated: list[Gated]) -> str:
    actions = sorted({a for a, _k in missing})
    repo_keys = sorted({k for _a, k in missing})
    by_repo: dict[str, list[str]] = {}
    for a, k in missing:
        by_repo.setdefault(k, []).append(a)
    ack_lines = []
    for k, acts in by_repo.items():
        ack_lines.append(f"   {ACK_BIN} {' '.join(sorted(set(acts)))} --repo {shlex.quote(k)}")
    staging_note = ""
    for g in gated:
        if g.action == "commit":
            staging_note = (
                "\nNOTE: the gate blocks the WHOLE Bash command. If this command also stages "
                "(git add) or does anything else before the commit, that part did NOT run. "
                "Stage in a separate Bash call first, then commit on its own.\n"
            )
            break
    notes = [n for n in (g.extra_note for g in gated) if n]
    note_text = ("\n" + "\n".join(f"NOTE: {n}." for n in notes) + "\n") if notes else ""
    return (
        f"publish-guard: BLOCKED. {', '.join(actions)} publishes text to a remote "
        f"({', '.join(repo_keys)}) and has no acknowledgement yet.\n"
        "\n"
        "Do all three steps, in this order, in the SAME assistant message:\n"
        "\n"
        "1. In your reply, quote the FULL text that will be published (commit message, "
        "PR/issue title and body, release notes, comment), then print the checklist below "
        "with every box ticked and a one-line justification per item. If any box cannot "
        "be ticked honestly, rewrite the text and start the checklist again.\n"
        "\n"
        f"{checklist_text()}\n"
        "\n"
        "2. Record the acknowledgement with a separate Bash call:\n"
        + "\n".join(ack_lines)
        + "\n"
        "\n"
        "3. Re-run the publish command unchanged.\n"
        f"{staging_note}{note_text}"
        "\n"
        "Acknowledgements are single-use, bound to this session, the action and the "
        f"repository, and expire after {TTL_SECONDS // 60} minutes. No flag disables this gate."
    )


def format_denylist(hits: list[Hit]) -> str:
    lines = [
        "publish-guard: BLOCKED. The text that would be published matches the denylist. "
        "No acknowledgement can override this; change the text.",
        "",
    ]
    for h in hits[:8]:
        lines.append(f"  [{h.pattern_id}] in {h.source}: {h.line}")
    if len(hits) > 8:
        lines.append(f"  ... and {len(hits) - 8} more")
    lines += [
        "",
        f"Pattern sources: {BUILTIN_PATTERNS} (builtin) and {CONFIG_DIR / 'denylist.txt'} (private).",
        "Rewrite the text so it carries no internal hostnames, usernames, addresses, paths, "
        "self-references or internal status, then try again.",
    ]
    return "\n".join(lines)


def run_hook(payload: dict, runner: Runner | None = None) -> int:
    runner = runner or Runner()
    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not command.strip():
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    session_id = payload.get("session_id") or ""

    def read_file(path: str) -> str:
        p = Path(os.path.expanduser(path))
        if not p.is_absolute():
            p = Path(cwd) / p
        return p.read_bytes()[:MAX_FILE_BYTES].decode("utf-8", errors="replace")

    classifier = Classifier(lambda: ShellScanner(read_file), cwd)
    try:
        gated = classifier.classify_text(command)
    except GuardError as e:
        if _legacy_gate_matches(command):
            audit(session_id, "deny-error", [], [], command)
            deny(f"publish-guard: BLOCKED. Could not parse this command safely ({e}). "
                 "Simplify the command so the published text is literal and inspectable.",
                 "publish-guard: command not parseable, blocked")
            return 0
        return 0  # unparseable but clearly not a publish command

    if not gated:
        return 0

    # L2: denylist
    extractor = Extractor(runner, read_file)
    sources: list[TextSource] = []
    repo_keys: list[str] = []
    for g in gated:
        sources.extend(extractor.extract(g))
        repo_keys.append(resolve_repo_key(g, runner))
    patterns = load_patterns(BUILTIN_PATTERNS, "builtin") + load_patterns(ensure_private_denylist(), "denylist")
    hits = scan_sources(sources, patterns)
    actions = [g.action for g in gated]
    if hits:
        audit(session_id, "deny-denylist", actions, repo_keys, command)
        deny(format_denylist(hits), f"publish-guard: denylist hit ({hits[0].pattern_id})")
        return 0

    # L1: acknowledgement
    store = AckStore(session_id)
    store.purge_expired()
    needed = sorted({(g.action, k) for g, k in zip(gated, repo_keys)})
    missing = [(a, k) for a, k in needed if not store.valid(a, k)]
    if missing:
        audit(session_id, "deny-noack", actions, repo_keys, command)
        deny(format_noack(missing, gated), f"publish-guard: {', '.join(a for a, _k in missing)} needs acknowledgement")
        return 0
    for a, k in needed:
        store.consume(a, k)
    audit(session_id, "allow", actions, repo_keys, command)
    return 0


LEGACY_RE = re.compile(
    r"(^|[\s;&|(`\"'])(git(\s+-\S+)*\s+(commit|push)\b|gh\s+(pr|issue|release|api|repo|gist)\b|glab\s+(mr|issue|release)\b)",
    re.S,
)


def _legacy_gate_matches(command: str) -> bool:
    return bool(LEGACY_RE.search(command))


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def cli_check(path: str | None) -> int:
    text = sys.stdin.read() if path in (None, "-") else Path(path).read_text(encoding="utf-8", errors="replace")
    patterns = load_patterns(BUILTIN_PATTERNS, "builtin") + load_patterns(ensure_private_denylist(), "denylist")
    hits = scan_sources([TextSource(path or "stdin", text)], patterns)
    if not hits:
        print("publish-guard: no denylist hits")
        return 0
    for h in hits:
        print(f"[{h.pattern_id}] {h.line}")
    return 1


def cli_classify(command: str) -> int:
    cwd = os.getcwd()
    classifier = Classifier(lambda: ShellScanner(lambda p: Path(p).read_text()), cwd)
    try:
        gated = classifier.classify_text(command)
    except GuardError as e:
        print(json.dumps({"error": str(e)}))
        return 2
    print(
        json.dumps(
            [
                {"action": g.action, "argv": g.argv, "git_dir": g.git_dir, "repo_hint": g.repo_hint, "note": g.extra_note}
                for g in gated
            ],
            indent=2,
        )
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--check":
        return cli_check(argv[2] if len(argv) > 2 else None)
    if len(argv) >= 3 and argv[1] == "--classify":
        return cli_classify(argv[2])
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as e:
        sys.stderr.write(f"publish-guard: cannot read hook input ({e}); blocking as a precaution\n")
        return 2
    try:
        return run_hook(payload)
    except GuardError as e:
        audit(payload.get("session_id") or "", "deny-error", [], [], (payload.get("tool_input") or {}).get("command") or "")
        sys.stderr.write(f"publish-guard: BLOCKED. {e}\n")
        return 2
    except Exception as e:  # noqa: BLE001 - fail closed on anything unexpected
        audit(payload.get("session_id") or "", "deny-error", [], [], (payload.get("tool_input") or {}).get("command") or "")
        sys.stderr.write(f"publish-guard: internal error ({type(e).__name__}: {e}); blocking as a precaution\n")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
