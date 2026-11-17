import random
import string
import subprocess

import pytest

from secretsniff.rules import shannon_entropy
from secretsniff.scanner import scan_git_history, scan_path, scan_text


def rnd(n, chars=string.ascii_letters + string.digits):
    return "".join(random.choice(chars) for _ in range(n))


def rules_of(findings):
    return {f.rule for f in findings}


def test_detects_common_secrets():
    text = "\n".join([
        "key = '" + "AKIA" + rnd(16, string.ascii_uppercase + string.digits) + "'",
        "token = '" + "ghp_" + rnd(36) + "'",
        "url = 'postgres://bob:" + rnd(10) + "@localhost/db'",
        "-----BEGIN RSA " + "PRIVATE KEY-----",
        'password = "' + rnd(10) + '"',
    ])
    found = rules_of(scan_text(text, "x.py", entropy=False))
    assert {"aws-access-key", "github-token", "db-url", "private-key", "generic-password"} <= found


def test_placeholders_are_ignored():
    text = ('password = "changeme"\nAPI_KEY = os.environ["API_KEY"]\n'
            'aws = "AKIAIOSFODNN7EXAMPLE"\napi_key = "your_api_key_here_123"\n')
    assert scan_text(text, "x.py") == []


def test_inline_ignore():
    line = 'token = "ghp_' + rnd(36) + '"  # secretsniff:ignore'
    assert scan_text(line, "x.py") == []


def test_entropy():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy(rnd(40)) > 4.5
    assert any(f.rule == "high-entropy" for f in scan_text('blob = "' + rnd(40) + '"', "x"))


def test_masking():
    f = scan_text("token = 'ghp_" + "A" * 36 + "'", "x", entropy=False)[0]
    assert f.masked.startswith("ghp_") and "*" in f.masked and "A" * 10 not in f.masked


def test_scan_folder_and_ignore_file(tmp_path):
    (tmp_path / "a.py").write_text("t = 'ghp_" + rnd(36) + "'\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "b.py").write_text("t = 'ghp_" + rnd(36) + "'\n")
    (tmp_path / "img.png").write_bytes(b"\x89PNG\x00ghp_" + b"A" * 36)
    (tmp_path / ".secretsniffignore").write_text("vendor/*\n")
    findings = scan_path(str(tmp_path), entropy=False)
    assert [f.file for f in findings] == ["a.py"]


@pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
                    reason="git not installed")
def test_secret_deleted_but_still_in_history(tmp_path):
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    secret = "ghp_" + rnd(36)
    (tmp_path / "conf.py").write_text(f"TOKEN = '{secret}'\n")
    git("add", ".")
    git("commit", "-qm", "add config")
    (tmp_path / "conf.py").write_text("import os\nTOKEN = os.environ['TOKEN']\n")
    git("commit", "-qam", "remove token")

    assert scan_path(str(tmp_path), entropy=False) == []          # current code is clean...
    history = scan_git_history(str(tmp_path))
    assert any(f.secret == secret and f.commit for f in history)  # ...but history is not
