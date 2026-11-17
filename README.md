# secretsniff

Scanner that looks for **secrets left in source code**: API keys, GitHub tokens, AWS keys, hard-coded passwords, SSH private keys… It can also dig through **the whole Git history**, where "deleted" secrets are still visible.

## Why I built this

Bots crawl GitHub non-stop to collect keys published by mistake. An AWS key pushed to a public repo can be abused within minutes. And deleting the line in a new commit isn't enough: it stays in the history. I wanted a simple tool to run before every `git push`, and to understand how tools like gitleaks or trufflehog work.

## What it detects

| Type | Examples |
|---|---|
| Cloud keys | AWS (`AKIA...` + secret key), Google API (`AIza...`) |
| Dev tokens | GitHub (`ghp_`, `github_pat_`), GitLab (`glpat-`) |
| Services | Slack (tokens and webhooks), Discord (webhooks), Stripe, SendGrid, OpenAI, Anthropic |
| Private keys | `-----BEGIN ... PRIVATE KEY-----` (RSA, OpenSSH, EC, PGP) |
| Connection strings | Database URL with a password (`postgres://user:<password>@server/db`) |
| Generic | `password = "..."`, `api_key = "..."`, JWT |
| Entropy | long random strings that look like a key (Shannon entropy detection) |

To avoid false positives, the tool:

- ignores example values (`changeme`, `your_api_key`, `AKIAIOSFODNN7EXAMPLE`, `os.environ[...]`…)
- skips binary files, images and folders like `node_modules`, `.venv` or `.git`
- **masks** secrets in the report (`ghp_************x9`), so they aren't exposed again in a terminal or CI log

## Compatibility

| System | Works? |
|---|---|
| Linux (all distributions) | Yes |
| macOS | Yes |
| Windows 10 / 11 | Yes |

## Requirements

- **Python 3.10 or newer**
- **Git**, only for the `--git` option (history scan)
- No external Python libraries

## Installation

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv pipx git
git clone https://github.com/aelof1/secretsniff.git
cd secretsniff
pipx install .
```

### Fedora

```bash
sudo dnf install -y python3 pipx git
```

### Arch

```bash
sudo pacman -S python python-pipx git
```

### macOS

```bash
brew install python pipx git
```

### Windows

Install [Python](https://www.python.org/downloads/) (tick "Add python.exe to PATH") and [Git for Windows](https://git-scm.com/download/win), then:

```powershell
cd secretsniff
pip install .
```

## Usage

```bash
secretsniff                       # scan the current folder
secretsniff ~/projects/my-api     # scan another folder
secretsniff . --git               # + the whole Git history
secretsniff . --no-entropy        # less noise (turns off entropy detection)
secretsniff . --min-severity high # serious findings only
secretsniff . --json              # JSON output
secretsniff . --reveal            # show secrets in clear text (careful)
```

Exit code: `0` if nothing is found, `1` otherwise, so it can block a commit or a pipeline.

### Try it with the demo

```bash
python3 tools/make_demo.py      # creates ./demo-project with FAKE secrets
secretsniff demo-project
```

```
[CRITICAL] config/settings.env:1
           AWS access key ID: AKIA************Y2
[CRITICAL] src/app.py:3
           GitHub token: ghp_************Qp
[HIGH    ] config/settings.env:3
           Database URL with password: kGoa******oz
[MEDIUM  ] src/app.py:5
           Hard-coded password: Sup3*****6J
...
8 potential secret(s) found.
```

The file `demo-project/src/safe.py` contains example values that must **not** be reported.

> The fake secrets are generated when the script runs instead of being written directly in the repository. Otherwise GitHub's push protection would block the push.

## Ignoring false positives

- On one line: add the comment `# secretsniff:ignore`
- For files or folders: create a `.secretsniffignore` file at the root of the project:

```
# one pattern per line
tests/fixtures/*
docs/*.md
```

## Run it before every commit (Git hook)

Create `.git/hooks/pre-commit` in your project:

```bash
#!/bin/sh
secretsniff . --no-entropy --min-severity medium || {
  echo "Commit blocked: secret detected."
  exit 1
}
```

Then: `chmod +x .git/hooks/pre-commit`

## I found a real secret, what now?

1. **Revoke it immediately** on the service's website (GitHub, AWS…). This is the most important step.
2. Create a new key and put it in an environment variable or a `.env` file ignored by Git.
3. If you want to remove it from the history: `git filter-repo` or BFG Repo-Cleaner. But always treat the secret as compromised.

## Project layout

```
secretsniff/
├── secretsniff/
│   ├── rules.py     # regular expressions + entropy calculation
│   ├── scanner.py   # walking files and the Git history
│   └── cli.py
├── tools/make_demo.py
└── tests/
```

## Tests

```bash
pip install pytest
python3 -m pytest
```

One of the tests creates a real temporary Git repository, commits a token, deletes it, and checks that the tool still finds it in the history.

## Limitations

- Pattern-based detection: a secret in an unknown format can slip through (entropy helps, but it's noisy).
- History scan is limited to the last 1000 commits by default.
- The tool doesn't check whether a key is still valid.

## License

MIT
