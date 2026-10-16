"""Tests for hooks/publish_guard.py. Run: python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))

import publish_guard as pg  # noqa: E402


def classify(cmd: str, files: dict[str, str] | None = None, cwd: str = "/work") -> list[str]:
    files = files or {}

    def reader(p: str) -> str:
        if p in files:
            return files[p]
        raise OSError(2, "no such file", p)

    c = pg.Classifier(lambda: pg.ShellScanner(reader), cwd)
    return [g.action for g in c.classify_text(cmd)]


def gated(cmd: str, cwd: str = "/work") -> list[pg.Gated]:
    c = pg.Classifier(lambda: pg.ShellScanner(lambda p: ""), cwd)
    return c.classify_text(cmd)


class FakeRunner(pg.Runner):
    """Returns canned output keyed by the first two git/gh args."""

    def __init__(self, table: dict[tuple[str, ...], str] | None = None):
        self.table = table or {}
        self.calls: list[list[str]] = []

    def run(self, argv, cwd=None):
        self.calls.append(argv)
        for key, out in self.table.items():
            if tuple(argv[: len(key)]) == key:
                return 0, out, ""
        return 1, "", f"fake: no entry for {argv[:3]}"


# --------------------------------------------------------------------------- #
# Classification                                                              #
# --------------------------------------------------------------------------- #


class TestClassifyGit(unittest.TestCase):
    def test_plain_commit_and_push(self):
        self.assertEqual(classify('git commit -m "x"'), ["commit"])
        self.assertEqual(classify("git push"), ["push"])
        self.assertEqual(classify("git push -u origin feat/x"), ["push"])

    def test_global_options_are_skipped(self):
        self.assertEqual(classify('git -C /srv/repo commit -S -m "x"'), ["commit"])
        self.assertEqual(classify("git -C /srv/repo -c core.hooksPath=/dev/null push"), ["push"])
        self.assertEqual(classify("git --git-dir .git --work-tree . commit -m x"), ["commit"])
        self.assertEqual(classify("git --git-dir=.git commit -m x"), ["commit"])
        self.assertEqual(classify("git -C/srv/repo commit -m x"), ["commit"])
        self.assertEqual(classify("git --no-pager -P commit -m x"), ["commit"])
        g = gated("git -C /srv/repo commit -m x")[0]
        self.assertEqual(g.git_dir, "/srv/repo")

    def test_relative_C_resolves_against_cwd(self):
        g = gated("git -C collections/common commit -m x", cwd="/work")[0]
        self.assertEqual(g.git_dir, "/work/collections/common")

    def test_cd_tracking(self):
        g = gated("cd /srv/repo && git commit -m x", cwd="/work")[0]
        self.assertEqual(g.cwd, "/srv/repo")
        g = gated("cd sub; git push", cwd="/work")[0]
        self.assertEqual(g.cwd, "/work/sub")

    def test_wrappers(self):
        for cmd in (
            "command git commit -m x",
            "\\git commit -m x",
            "/usr/bin/git commit -m x",
            "env GIT_EDITOR=true git commit -m x",
            "FOO=1 BAR=2 git commit -m x",
            "nohup git push",
            "timeout 60 git push",
            "timeout -s KILL 60 git push",
            "nice -n 5 git push",
            "sudo -u deploy git push",
            "xargs -I{} git commit -m {}",
            "time git push",
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(len(classify(cmd)), 1, cmd)

    def test_bundled_add_and_commit(self):
        self.assertEqual(classify("git add -A && git commit -m x"), ["commit"])
        self.assertEqual(classify('git add . ; git commit -m "x" ; git push'), ["commit", "push"])

    def test_not_gated(self):
        for cmd in (
            "git status",
            "git log --oneline",
            "git add -A",
            "git diff --cached",
            "git commit --help",
            "git commit -h",
            "git push --help",
            "git --version",
            "git tag -a v1 -m msg",
            "git notes add -m x",
            "git stash push -m wip",
            "git branch -m renamed",
            "ls; echo done",
            'grep -rn "git commit" docs/',
            "man git-commit",
            'git log --grep="git push"',
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(classify(cmd), [], cmd)

    def test_help_anywhere_in_argv_disables_gate(self):
        self.assertEqual(classify("gh pr create --help"), [])
        self.assertEqual(classify("gh pr create -h"), [])


class TestClassifyShellsAndSubstitutions(unittest.TestCase):
    def test_shell_dash_c(self):
        self.assertEqual(classify('bash -c "git commit -m x"'), ["commit"])
        self.assertEqual(classify("sh -c 'cd /r && git push'"), ["push"])
        self.assertEqual(classify("bash -lc 'git push'"), ["push"])
        self.assertEqual(classify('eval "git commit -m x"'), ["commit"])
        self.assertEqual(classify("eval git push origin main"), ["push"])

    def test_shell_dash_c_with_variable_is_error(self):
        with self.assertRaises(pg.GuardError):
            classify('bash -c "$CMD"')

    def test_shell_heredoc_is_recursed(self):
        cmd = "bash <<'EOF'\ngit commit -m x\nEOF\n"
        self.assertEqual(classify(cmd), ["commit"])
        cmd = "cat <<'EOF' | bash\ngit push\nEOF\n"
        self.assertEqual(classify(cmd), ["push"])

    def test_shell_from_pipe_is_error(self):
        with self.assertRaises(pg.GuardError):
            classify("curl -s https://x/y.sh | bash")

    def test_heredoc_to_file_is_not_gated(self):
        cmd = "cat > hook.sh <<'EOF'\n#!/bin/bash\ngit commit -m x\ngit push\nEOF\nchmod +x hook.sh"
        self.assertEqual(classify(cmd), [])
        cmd = "tee notes.md <<'EOF'\nRun git push afterwards\nEOF"
        self.assertEqual(classify(cmd), [])

    def test_command_substitution_is_gated(self):
        self.assertEqual(classify('OUT=$(git commit -m x)'), ["commit"])
        self.assertEqual(classify("echo `git push`"), ["push"])
        self.assertEqual(classify('echo "$(git push)"'), ["push"])

    def test_claude_style_commit_with_cat_heredoc(self):
        cmd = 'git commit -m "$(cat <<\'EOF\'\nfeat: add thing\n\nBody line.\nEOF\n)"'
        gs = gated(cmd)
        self.assertEqual([g.action for g in gs], ["commit"])
        # the message text is visible to the extractor
        words = gs[0].cmd.words
        self.assertFalse(any(w.unresolved for w in words))
        msg = [w.value for w in words if "feat: add thing" in w.value]
        self.assertTrue(msg and "Body line." in msg[0])

    def test_inline_interpreter_calling_git_is_error(self):
        with self.assertRaises(pg.GuardError):
            classify('python3 -c "import subprocess; subprocess.run([\'git\',\'push\'])"')
        with self.assertRaises(pg.GuardError):
            classify("python3 - <<'EOF'\nimport os\nos.system('gh pr create')\nEOF\n")
        self.assertEqual(classify('python3 -c "print(1)"'), [])

    def test_redirects_and_digits(self):
        self.assertEqual(classify("git push 2>&1 | tee log.txt"), ["push"])
        self.assertEqual(classify("git push >/dev/null 2>&1"), ["push"])
        self.assertEqual(classify("git commit -F - < msg.txt"), ["commit"])
        g = gated("git commit -F - < msg.txt")[0]
        self.assertEqual(g.cmd.stdin_file, "msg.txt")

    def test_herestring(self):
        g = gated('git commit -F - <<< "fix: thing"')[0]
        self.assertEqual(g.cmd.herestring, "fix: thing")

    def test_unbalanced_quote_raises(self):
        with self.assertRaises(pg.GuardError):
            classify('git commit -m "oops')


class TestClassifyGh(unittest.TestCase):
    def test_table(self):
        cases = {
            'gh pr create --title t --body b': ["pr-create", "push"],
            "gh pr merge 12 --squash": ["pr-merge"],
            "gh pr edit 12 --body x": ["pr-edit"],
            "gh pr comment 12 -b hi": ["pr-comment"],
            "gh pr review 12 --approve -b lgtm": ["pr-review"],
            "gh pr close 12 --comment done": ["pr-close"],
            "gh issue create -t t -b b": ["issue-create"],
            "gh issue edit 3 --title t": ["issue-edit"],
            "gh issue comment 3 -b hi": ["issue-comment"],
            "gh issue close 3 -c done": ["issue-close"],
            "gh release create v1.0.0 --notes 'x'": ["release"],
            "gh release edit v1.0.0 --notes x": ["release"],
            "gh repo edit --description x": ["repo-edit"],
            "gh gist create file.txt": ["gist"],
            "gh -R owner/repo issue comment 3 -b hi": ["issue-comment"],
            "gh issue comment 3 -R owner/repo -b hi": ["issue-comment"],
        }
        for cmd, expected in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(classify(cmd), expected)

    def test_repo_hint(self):
        g = gated("gh issue comment 3 -R owner/repo -b hi")[0]
        self.assertEqual(g.repo_hint, "owner/repo")
        g = gated("gh --repo=owner/repo pr merge 1")[0]
        self.assertEqual(g.repo_hint, "owner/repo")

    def test_gh_api(self):
        self.assertEqual(classify("gh api repos/o/r/issues -f title=x -f body=y"), ["api"])
        self.assertEqual(classify("gh api -X PATCH repos/o/r/pulls/1 -f body=y"), ["api"])
        self.assertEqual(classify("gh api --method POST repos/o/r/releases --input body.json"), ["api"])
        self.assertEqual(classify("gh api graphql -f query='mutation { x }'"), ["api"])
        self.assertEqual(classify("gh api repos/o/r/pulls/1"), [])
        self.assertEqual(classify("gh api -X GET repos/o/r/issues"), [])
        self.assertEqual(classify("gh api repos/o/r --jq .name"), [])

    def test_gh_read_only(self):
        for cmd in (
            "gh pr view 12",
            "gh pr list",
            "gh pr checks 12 --watch",
            "gh pr diff 12",
            "gh pr ready 12",
            "gh pr checkout 12",
            "gh issue list",
            "gh issue view 3",
            "gh release list",
            "gh release view v1",
            "gh repo view",
            "gh run list",
            "gh auth status",
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(classify(cmd), [], cmd)

    def test_glab(self):
        self.assertEqual(classify("glab mr create -t t -d d"), ["pr-create"])
        self.assertEqual(classify("glab mr note 3 -m hi"), ["pr-comment"])
        self.assertEqual(classify("glab issue create -t t"), ["issue-create"])
        self.assertEqual(classify("glab release create v1 -n notes"), ["release"])
        self.assertEqual(classify("glab mr list"), [])


# --------------------------------------------------------------------------- #
# Extraction                                                                  #
# --------------------------------------------------------------------------- #


class TestExtractCommit(unittest.TestCase):
    def extract(self, cmd: str, runner=None, files=None):
        files = files or {}
        reader = lambda p: files[p]  # noqa: E731
        c = pg.Classifier(lambda: pg.ShellScanner(reader), "/work")
        gs = c.classify_text(cmd)
        ex = pg.Extractor(runner or FakeRunner(), reader)
        out = []
        for g in gs:
            out.extend(ex.extract(g))
        return out

    def texts(self, sources):
        return [s.text for s in sources]

    def test_messages(self):
        self.assertEqual(self.texts(self.extract('git commit -m "fix: a" -m "body"')), ["fix: a", "body"])
        self.assertEqual(self.texts(self.extract("git commit -m'fix: b'")), ["fix: b"])
        self.assertEqual(self.texts(self.extract("git commit --message=fix:c")), ["fix:c"])
        self.assertEqual(self.texts(self.extract("git commit -S -s -a --message 'fix: d'")), ["fix: d"])

    def test_cat_heredoc_message(self):
        cmd = 'git commit -m "$(cat <<\'EOF\'\nfeat: x\n\nLonger body.\nEOF\n)"'
        self.assertEqual(self.texts(self.extract(cmd)), ["feat: x\n\nLonger body.\n"])

    def test_F_dash_heredoc_and_herestring(self):
        cmd = "git commit -F - <<'EOF'\nfeat: y\nEOF\n"
        self.assertEqual(self.texts(self.extract(cmd)), ["feat: y\n"])
        cmd = "git commit -F - <<< 'feat: z'"
        self.assertEqual(self.texts(self.extract(cmd)), ["feat: z\n"])

    def test_F_dash_from_pipe(self):
        self.assertEqual(self.texts(self.extract("printf 'feat: p' | git commit -F -")), ["feat: p\n"])
        self.assertEqual(self.texts(self.extract("echo fix: q | git commit -F -")), ["fix: q\n"])
        with self.assertRaises(pg.GuardError):
            self.extract("some-generator | git commit -F -")

    def test_F_file(self):
        out = self.extract("git commit -F msg.txt", files={"/work/msg.txt": "from file"})
        self.assertEqual(self.texts(out), ["from file"])
        out = self.extract("git -C /srv/r commit -F msg.txt", files={"/srv/r/msg.txt": "rel to -C"})
        self.assertEqual(self.texts(out), ["rel to -C"])

    def test_variable_message_is_error(self):
        with self.assertRaises(pg.GuardError):
            self.extract('git commit -m "$MSG"')
        with self.assertRaises(pg.GuardError):
            self.extract('git commit -m "$(generate-msg)"')

    def test_amend_and_reuse(self):
        r = FakeRunner({("git", "log"): "old message\n"})
        self.assertEqual(self.texts(self.extract("git commit --amend --no-edit", runner=r)), ["old message\n"])
        self.assertEqual(self.texts(self.extract("git commit --amend -m new", runner=r)), ["new"])
        self.assertEqual(self.texts(self.extract("git commit -C abc123", runner=r)), ["old message\n"])
        out = self.extract("git commit --fixup=abc123", runner=r)
        self.assertEqual(self.texts(out), ["fixup! ", "old message\n"])

    def test_unresolved_git_C_is_error(self):
        with self.assertRaises(pg.GuardError):
            classify('git -C "$C" commit -m x')


class TestExtractPush(unittest.TestCase):
    def test_unpushed_commits_and_branch(self):
        listing = "commit 1111111111111111\nfeat: one\n\nbody one\n\x00\ncommit 2222222222222222\nfix: two\n\x00\n"
        r = FakeRunner(
            {
                ("git", "rev-parse", "--git-dir"): ".git\n",
                ("git", "rev-list"): listing,
                ("git", "rev-parse", "--abbrev-ref"): "feat/x\n",
                ("git", "symbolic-ref"): "feat/x\n",
                ("git", "config"): "",
            }
        )
        g = gated("git push -u origin feat/x")[0]
        out = pg.Extractor(r, lambda p: "").extract(g)
        labels = [s.label for s in out]
        self.assertIn("refspec", labels)
        self.assertEqual(sum(1 for s in out if s.label.startswith("unpushed commit")), 2)
        self.assertIn("feat: one\n\nbody one", [s.text for s in out])
        self.assertIn("branch name", labels)
        rev = next(c for c in r.calls if c[1] == "rev-list")
        self.assertIn("--remotes=origin", rev)

    def test_push_option_is_text(self):
        r = FakeRunner({("git", "rev-parse", "--git-dir"): ".git\n", ("git", "rev-list"): ""})
        g = gated("git push -o 'merge_request.description=on my workstation'")[0]
        out = pg.Extractor(r, lambda p: "").extract(g)
        self.assertIn("merge_request.description=on my workstation", [s.text for s in out])

    def test_not_a_repo_is_error(self):
        g = gated("git push")[0]
        with self.assertRaises(pg.GuardError):
            pg.Extractor(FakeRunner(), lambda p: "").extract(g)


class TestExtractGh(unittest.TestCase):
    def test_pr_create_flags_and_fill(self):
        r = FakeRunner(
            {
                ("git", "symbolic-ref"): "origin/main\n",
                ("git", "log"): "feat: a\x00fix: b\x00",
                ("git", "rev-parse", "--abbrev-ref"): "feat/a\n",
                ("git", "rev-parse", "--git-dir"): ".git\n",
                ("git", "rev-list"): "",
            }
        )
        gs = gated('gh pr create --title "T" --body "B" --fill')
        out = []
        for g in gs:
            out.extend(pg.Extractor(r, lambda p: "").extract(g))
        joined = "\n".join(s.text for s in out)
        self.assertIn("T", joined)
        self.assertIn("B", joined)
        self.assertIn("feat: a", joined)
        self.assertIn("feat/a", joined)

    def test_pr_create_body_file_dash_heredoc(self):
        r = FakeRunner({("git", "rev-parse", "--abbrev-ref"): "b\n", ("git", "rev-parse", "--git-dir"): ".git\n", ("git", "rev-list"): ""})
        cmd = "gh pr create -t T -F - <<'EOF'\nPR body here\nEOF\n"
        gs = gated(cmd)
        out = pg.Extractor(r, lambda p: "").extract(gs[0])
        self.assertIn("PR body here\n", [s.text for s in out])

    def test_pr_merge_live_fetch(self):
        data = {
            "title": "Live title",
            "body": "Live body edited in web UI",
            "headRefName": "feat/live",
            "commits": [{"oid": "abcdef1234567890", "messageHeadline": "feat: c", "messageBody": "details"}],
        }
        r = FakeRunner({("gh", "pr", "view"): json.dumps(data)})
        g = gated("gh pr merge 42 --squash --delete-branch -R owner/repo")[0]
        out = pg.Extractor(r, lambda p: "").extract(g)
        texts = [s.text for s in out]
        self.assertIn("Live title", texts)
        self.assertIn("Live body edited in web UI", texts)
        self.assertIn("feat: c\ndetails", texts)
        call = next(c for c in r.calls if c[:3] == ["gh", "pr", "view"])
        self.assertIn("42", call)
        self.assertIn("owner/repo", call)

    def test_pr_merge_offline_is_error(self):
        g = gated("gh pr merge 42")[0]
        with self.assertRaises(pg.GuardError):
            pg.Extractor(FakeRunner(), lambda p: "").extract(g)

    def test_api_fields(self):
        g = gated("gh api repos/o/r/issues -f title='T' -F body=@body.md -f labels[]=bug")[0]
        out = pg.Extractor(FakeRunner(), lambda p: "BODY FROM FILE").extract(g)
        texts = [s.text for s in out]
        self.assertIn("BODY FROM FILE", texts)
        self.assertIn("title=T", texts)

    def test_generic_comment(self):
        g = gated("gh issue comment 3 -b 'hello there'")[0]
        out = pg.Extractor(FakeRunner(), lambda p: "").extract(g)
        self.assertIn("hello there", out[-1].text)

    def test_release_notes_file(self):
        g = gated("gh release create v1.0.0 --title 'v1.0.0' -F CHANGELOG.md")[0]
        out = pg.Extractor(FakeRunner(), lambda p: "## Changes\n- x").extract(g)
        self.assertIn("## Changes\n- x", [s.text for s in out])


# --------------------------------------------------------------------------- #
# Denylist                                                                    #
# --------------------------------------------------------------------------- #


class TestDenylist(unittest.TestCase):
    def test_builtin_file_loads(self):
        pats = pg.load_patterns(ROOT / "patterns" / "builtin.txt", "builtin")
        self.assertGreater(len(pats), 10)
        self.assertTrue(any(p.section == "messages-only" for p in pats))

    def test_sections_and_hits(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# c\n[always]\n\\bbastion01\\b\n[messages-only]\n\\bthe customer\\b\n")
            path = Path(fh.name)
        try:
            pats = pg.load_patterns(path, "denylist")
            self.assertEqual([p.section for p in pats], ["always", "messages-only"])
            hits = pg.scan_sources([pg.TextSource("m", "Deploy to Bastion01 tonight")], pats)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].pattern_id, "denylist:3")
            self.assertEqual(pg.scan_sources([pg.TextSource("m", "bastion01exporter")], pats), [])
            # a word boundary sits between the name and a hyphen: this IS a hit
            self.assertEqual(len(pg.scan_sources([pg.TextSource("m", "bastion01-exporter")], pats)), 1)
        finally:
            path.unlink()

    def test_builtin_catches_checklist_phrases(self):
        pats = pg.load_patterns(ROOT / "patterns" / "builtin.txt", "builtin")
        for text in (
            "works on my workstation",
            "tabletop still in dev",
            "WIP: do not merge",
            "see /home/alice/repo",
            "host at 192.168.1.10",
            "ping 10.0.0.5 first",
            "contact alice@example.org",
            "this is out of scope",
            "not listed because it is internal",
            "intentionally left out",
            "as in inventory",
            "we have three nodes",
        ):
            with self.subTest(text=text):
                self.assertTrue(pg.scan_sources([pg.TextSource("m", text)], pats), text)

    def test_builtin_does_not_flag_normal_text(self):
        pats = pg.load_patterns(ROOT / "patterns" / "builtin.txt", "builtin")
        for text in (
            "feat(common): add storage role",
            "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>",
            "Fixes #123",
            "Use `ansible.builtin.file` instead of `shell`",
            "Default port 8080; version 1.2.3",
            "See https://github.com/marcstraube/ansible-collection-common",
            "Signed-off-by: Someone <someone@example.org>",
        ):
            with self.subTest(text=text):
                self.assertEqual(pg.scan_sources([pg.TextSource("m", text)], pats), [], text)

    def test_invalid_regex_is_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("[always]\n(unclosed\n")
            path = Path(fh.name)
        try:
            with self.assertRaises(pg.GuardError):
                pg.load_patterns(path, "denylist")
        finally:
            path.unlink()


# --------------------------------------------------------------------------- #
# Sentinels                                                                   #
# --------------------------------------------------------------------------- #


class TestAckStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_lifecycle(self):
        store = pg.AckStore("sess-1", self.base)
        self.assertFalse(store.valid("commit", "/r"))
        store.dir.mkdir(parents=True)
        store.path("commit", "/r").write_text("{}")
        self.assertTrue(store.valid("commit", "/r"))
        self.assertFalse(store.valid("push", "/r"))
        self.assertFalse(store.valid("commit", "/other"))
        self.assertFalse(pg.AckStore("sess-2", self.base).valid("commit", "/r"))
        store.consume("commit", "/r")
        self.assertFalse(store.valid("commit", "/r"))

    def test_ttl(self):
        store = pg.AckStore("sess-1", self.base)
        store.dir.mkdir(parents=True)
        p = store.path("push", "/r")
        p.write_text("{}")
        old = time.time() - pg.TTL_SECONDS - 5
        os.utime(p, (old, old))
        self.assertFalse(store.valid("push", "/r"))
        store.purge_expired()
        self.assertFalse(p.exists())

    def test_purge_sweeps_other_sessions_and_empty_dirs(self):
        old = time.time() - pg.TTL_SECONDS - 5
        # finished session with one expired ack: file and dir go away
        dead = pg.AckStore("dead", self.base)
        dead.dir.mkdir(parents=True)
        stale = dead.path("commit", "/r")
        stale.write_text("{}")
        os.utime(stale, (old, old))
        os.utime(dead.dir, (old, old))
        # finished session that never acked: empty old dir goes away
        empty = self.base / "empty"
        empty.mkdir()
        os.utime(empty, (old, old))
        # live session with a fresh ack stays; fresh empty dir stays
        live = pg.AckStore("live", self.base)
        live.dir.mkdir(parents=True)
        fresh = live.path("push", "/r")
        fresh.write_text("{}")
        (self.base / "fresh-empty").mkdir()
        pg.AckStore("me", self.base).purge_expired()
        self.assertFalse(stale.exists())
        self.assertFalse(dead.dir.exists())
        self.assertFalse(empty.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue((self.base / "fresh-empty").exists())

    def test_purge_keeps_dir_with_non_json_file(self):
        old = time.time() - pg.TTL_SECONDS - 5
        d = self.base / "odd"
        d.mkdir()
        stray = d / "notes.txt"
        stray.write_text("x")
        os.utime(stray, (old, old))
        os.utime(d, (old, old))
        pg.AckStore("me", self.base).purge_expired()
        self.assertTrue(stray.exists())
        self.assertTrue(d.exists())

    def test_audit_rotates_beyond_max_bytes(self):
        data = self.base / "data"
        with mock.patch.object(pg, "DATA_DIR", data), \
             mock.patch.object(pg, "AUDIT_MAX_BYTES", 200):
            for _ in range(5):
                pg.audit("sess-1234", "allow", ["commit"], ["/r"], "sample command text")
            log = data / "audit.log"
            self.assertTrue((data / "audit.log.1").exists())
            self.assertTrue(log.exists())
            self.assertLessEqual(log.stat().st_size, 200 + 160)
            self.assertNotIn("audit.log.2", {q.name for q in data.iterdir()})

    def test_bash_ack_script_matches_python_layout(self):
        env = {
            **os.environ,
            "XDG_RUNTIME_DIR": str(self.base),
            "CLAUDE_CODE_SESSION_ID": "sess-bash",
        }
        repo = self.base / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        res = subprocess.run(
            [str(ROOT / "bin" / "publish-guard-ack"), "commit", "push", "--repo", str(repo)],
            env=env, capture_output=True, text=True, cwd=str(self.base),
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        store = pg.AckStore("sess-bash", self.base / "publish-guard")
        key = os.path.realpath(str(repo))
        self.assertTrue(store.valid("commit", key))
        self.assertTrue(store.valid("push", key))
        self.assertFalse(store.valid("pr-create", key))
        # owner/repo form
        res = subprocess.run(
            [str(ROOT / "bin" / "publish-guard-ack"), "issue-comment", "--repo", "owner/repo"],
            env=env, capture_output=True, text=True, cwd=str(self.base),
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(store.valid("issue-comment", "owner/repo"))
        # unknown action rejected
        res = subprocess.run([str(ROOT / "bin" / "publish-guard-ack"), "bogus"], env=env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        # status lists them
        res = subprocess.run([str(ROOT / "bin" / "publish-guard-ack"), "--status"], env=env, capture_output=True, text=True)
        self.assertIn("issue-comment", res.stdout)


# --------------------------------------------------------------------------- #
# End-to-end hook behaviour with a real temporary git repository              #
# --------------------------------------------------------------------------- #


class TestHookEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.runtime = base / "runtime"
        self.runtime.mkdir()
        self.config = base / "config"
        self.data = base / "data"
        self.repo = base / "repo"
        self.remote = base / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(self.remote)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        self._git("config", "user.email", "t@example.invalid")
        self._git("config", "user.name", "T")
        self._git("config", "commit.gpgsign", "false")
        self._git("remote", "add", "origin", str(self.remote))
        (self.repo / "a.txt").write_text("a\n")
        self._git("add", "a.txt")
        self._git("commit", "-q", "-m", "chore: initial")
        self._git("push", "-q", "-u", "origin", "main")
        self._old_env = dict(os.environ)
        os.environ["XDG_RUNTIME_DIR"] = str(self.runtime)
        self._patch = {
            "CONFIG_DIR": pg.CONFIG_DIR,
            "DATA_DIR": pg.DATA_DIR,
        }
        pg.CONFIG_DIR = self.config
        pg.DATA_DIR = self.data
        self.config.mkdir()
        (self.config / "denylist.txt").write_text("[always]\n\\bbastion01\\b\n\\bjdoe\\b\n")
        self.session = "sess-e2e"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        pg.CONFIG_DIR = self._patch["CONFIG_DIR"]
        pg.DATA_DIR = self._patch["DATA_DIR"]
        self.tmp.cleanup()

    def _git(self, *args):
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def hook(self, command: str, cwd: str | None = None) -> dict | None:
        payload = {
            "session_id": self.session,
            "cwd": cwd or str(self.repo),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = pg.run_hook(payload)
        self.assertEqual(rc, 0)
        out = buf.getvalue().strip()
        return json.loads(out) if out else None

    def decision(self, result):
        return None if result is None else result["hookSpecificOutput"]["permissionDecision"]

    def ack(self, *actions):
        store = pg.AckStore(self.session)
        store.dir.mkdir(parents=True, exist_ok=True)
        key = os.path.realpath(str(self.repo))
        for a in actions:
            store.path(a, key).write_text("{}")

    def test_non_publish_commands_pass_silently(self):
        self.assertIsNone(self.hook("git status"))
        self.assertIsNone(self.hook("ls -la"))
        self.assertIsNone(self.hook("cat > x.sh <<'EOF'\ngit commit -m hi\nEOF\n"))

    def test_commit_without_ack_is_denied_with_checklist(self):
        (self.repo / "b.txt").write_text("b\n")
        self._git("add", "b.txt")
        res = self.hook('git commit -m "feat: add b"')
        self.assertEqual(self.decision(res), "deny")
        reason = res["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("ABOUT TO PUBLISH", reason)
        self.assertIn("publish-guard-ack commit --repo", reason)
        self.assertIn("Stage in a separate Bash call", reason)
        self.assertTrue((self.data / "audit.log").exists())
        self.assertIn("deny-noack", (self.data / "audit.log").read_text())

    def test_commit_with_ack_is_allowed_once(self):
        (self.repo / "b.txt").write_text("b\n")
        self._git("add", "b.txt")
        self.ack("commit")
        self.assertIsNone(self.hook('git commit -m "feat: add b"'))
        # consumed: second attempt is denied again
        res = self.hook('git commit -m "feat: add b again"')
        self.assertEqual(self.decision(res), "deny")
        self.assertIn("allow", (self.data / "audit.log").read_text())

    def test_wrong_action_ack_does_not_count(self):
        self.ack("push")
        res = self.hook('git commit -m "feat: x"')
        self.assertEqual(self.decision(res), "deny")
        self.assertIn("needs acknowledgement", res["systemMessage"])

    def test_other_session_ack_does_not_count(self):
        other = pg.AckStore("someone-else")
        other.dir.mkdir(parents=True)
        other.path("commit", os.path.realpath(str(self.repo))).write_text("{}")
        self.assertEqual(self.decision(self.hook('git commit -m "feat: x"')), "deny")

    def test_denylist_hit_blocks_even_with_ack_and_keeps_ack(self):
        self.ack("commit")
        res = self.hook('git commit -m "fix: works on my workstation"')
        self.assertEqual(self.decision(res), "deny")
        self.assertIn("denylist", res["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertIn("builtin:", res["systemMessage"])
        # ack not consumed by a denylist denial
        store = pg.AckStore(self.session)
        self.assertTrue(store.valid("commit", os.path.realpath(str(self.repo))))
        # private denylist hit
        res = self.hook('git commit -m "fix: tune bastion01 retention"')
        self.assertIn("denylist:", res["systemMessage"])

    def test_claude_style_heredoc_message_is_scanned(self):
        self.ack("commit")
        cmd = 'git commit -m "$(cat <<\'EOF\'\nfeat: thing\n\nTested live on jdoe laptop.\nEOF\n)"'
        res = self.hook(cmd)
        self.assertEqual(self.decision(res), "deny")
        self.assertIn("denylist", res["hookSpecificOutput"]["permissionDecisionReason"])

    def test_push_scans_unpushed_commit_messages(self):
        (self.repo / "c.txt").write_text("c\n")
        self._git("add", "c.txt")
        self._git("commit", "-q", "-m", "feat: migrate bastion01 host")
        self.ack("push")
        res = self.hook("git push")
        self.assertEqual(self.decision(res), "deny")
        self.assertIn("unpushed commit", res["hookSpecificOutput"]["permissionDecisionReason"])
        # clean commit on top does not rescue the dirty one
        (self.repo / "d.txt").write_text("d\n")
        self._git("add", "d.txt")
        self._git("commit", "-q", "-m", "feat: fine")
        self.assertEqual(self.decision(self.hook("git push origin main")), "deny")

    def test_push_clean_with_ack_allowed(self):
        (self.repo / "c.txt").write_text("c\n")
        self._git("add", "c.txt")
        self._git("commit", "-q", "-m", "feat: fine")
        self.assertEqual(self.decision(self.hook("git push")), "deny")
        self.ack("push")
        self.assertIsNone(self.hook("git push"))

    def test_git_C_form_from_other_cwd(self):
        (self.repo / "b.txt").write_text("b\n")
        self._git("add", "b.txt")
        self.ack("commit")
        cmd = f'git -C {self.repo} commit -S --no-gpg-sign -m "feat: add b"'
        self.assertIsNone(self.hook(cmd, cwd=self.tmp.name))

    def test_bundled_add_commit_denied_with_hint(self):
        (self.repo / "b.txt").write_text("b\n")
        res = self.hook('git add b.txt && git commit -m "feat: b"')
        self.assertEqual(self.decision(res), "deny")
        self.assertIn("did NOT run", res["hookSpecificOutput"]["permissionDecisionReason"])

    def test_commit_and_push_need_both_acks(self):
        (self.repo / "b.txt").write_text("b\n")
        self._git("add", "b.txt")
        self.ack("commit")
        res = self.hook('git commit -m "feat: b" && git push')
        self.assertEqual(self.decision(res), "deny")
        self.assertIn("publish-guard-ack push", res["hookSpecificOutput"]["permissionDecisionReason"])
        self.ack("push")
        self.assertIsNone(self.hook('git commit -m "feat: b" && git push'))

    def test_variable_message_is_blocked_as_error(self):
        buf = io.StringIO()
        payload = {"session_id": self.session, "cwd": str(self.repo), "tool_name": "Bash",
                   "tool_input": {"command": 'git commit -m "$MSG"'}}
        with redirect_stdout(buf):
            with self.assertRaises(pg.GuardError):
                pg.run_hook(payload)

    def test_script_main_fail_closed_on_garbage_stdin(self):
        res = subprocess.run([sys.executable, str(ROOT / "hooks" / "publish_guard.py")], input="not json",
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)
        self.assertIn("blocking", res.stderr)

    def test_script_main_error_exit_2(self):
        payload = json.dumps({"session_id": "s", "cwd": str(self.repo), "tool_name": "Bash",
                              "tool_input": {"command": 'git commit -m "$MSG"'}})
        env = {**os.environ, "CLAUDE_PLUGIN_DATA": str(self.data), "CLAUDE_PLUGIN_OPTION_CONFIG_DIR": str(self.config)}
        res = subprocess.run([sys.executable, str(ROOT / "hooks" / "publish_guard.py")], input=payload,
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 2)
        self.assertIn("BLOCKED", res.stderr)

    def test_check_cli(self):
        env = {**os.environ, "CLAUDE_PLUGIN_OPTION_CONFIG_DIR": str(self.config)}
        res = subprocess.run([str(ROOT / "bin" / "publish-guard-check"), "-"], input="fine text\n",
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        res = subprocess.run([str(ROOT / "bin" / "publish-guard-check"), "-"], input="still in dev\n",
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 1)
        res = subprocess.run([str(ROOT / "bin" / "publish-guard-check"), "--classify", "git push origin main"],
                             capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('"push"', res.stdout)

    def test_private_denylist_template_created_when_missing(self):
        (self.config / "denylist.txt").unlink()
        self.assertIsNone(self.hook("git status"))  # not gated, no creation needed
        self.ack("commit")
        (self.repo / "b.txt").write_text("b\n")
        self._git("add", "b.txt")
        self.assertIsNone(self.hook('git commit -m "feat: b"'))
        self.assertTrue((self.config / "denylist.txt").exists())
        self.assertEqual((self.config / "denylist.txt").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
