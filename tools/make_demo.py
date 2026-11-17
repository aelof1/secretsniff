"""Create a small demo project full of FAKE secrets in ./demo-project

The fake keys are built at runtime on purpose: if they were written as-is in
this repository, GitHub's own secret scanning would (rightly) complain.
"""

import random
import string
from pathlib import Path

random.seed(1)


def rnd(n, chars=string.ascii_letters + string.digits):
    return "".join(random.choice(chars) for _ in range(n))


demo = Path("demo-project")
(demo / "src").mkdir(parents=True, exist_ok=True)
(demo / "config").mkdir(exist_ok=True)

(demo / "src" / "app.py").write_text(f'''import requests

GITHUB_TOKEN = "{"ghp_" + rnd(36)}"
API_KEY = "{rnd(32)}"
password = "{"Sup3r" + rnd(6)}"

def get_user():
    return requests.get("https://api.github.com/user", headers={{"Authorization": GITHUB_TOKEN}})
''')

(demo / "config" / "settings.env").write_text(f"""AWS_ACCESS_KEY_ID={"AKIA" + rnd(16, string.ascii_uppercase + string.digits)}
aws_secret_access_key={rnd(40)}
DATABASE_URL=postgres://admin:{rnd(12)}@db.internal:5432/prod
SLACK_WEBHOOK=https://hooks.slack.com/services/T{rnd(8, string.ascii_uppercase)}/B{rnd(8, string.ascii_uppercase)}/{rnd(24)}
""")

(demo / "config" / "deploy_key").write_text(
    "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + rnd(64) + "\n-----END OPENSSH PRIVATE KEY-----\n")

# things that must NOT be reported
(demo / "src" / "safe.py").write_text('''import os
API_KEY = os.environ["API_KEY"]
password = "changeme"
example = "AKIAIOSFODNN7EXAMPLE"
''')
print(f"Demo project created in {demo.resolve()}")
