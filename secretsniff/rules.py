"""Detection rules: regular expressions for well-known secret formats."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    regex: re.Pattern
    severity: str = "high"


RULES = [
    Rule("aws-access-key", "AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    Rule("aws-secret-key", "AWS secret access key",
         re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), "critical"),
    Rule("github-token", "GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), "critical"),
    Rule("github-fine-grained", "GitHub fine-grained token",
         re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "critical"),
    Rule("gitlab-token", "GitLab personal token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"), "critical"),
    Rule("slack-token", "Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("slack-webhook", "Slack webhook",
         re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    Rule("discord-webhook", "Discord webhook",
         re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")),
    Rule("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Rule("stripe-secret", "Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), "critical"),
    Rule("openai-key", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    Rule("anthropic-key", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    Rule("sendgrid-key", "SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    Rule("private-key", "Private key file content",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
    Rule("jwt", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
         "medium"),
    Rule("db-url", "Database URL with password",
         re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:([^@\s]{3,})@"), "high"),
    Rule("generic-password", "Hard-coded password",
         re.compile(r"(?i)\b(?:password|passwd|pwd|mot_de_passe)\s*[:=]\s*['\"]([^'\"\s\\]{6,64})['\"]"), "medium"),
    Rule("generic-secret", "Hard-coded secret / API key",
         re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
                    r"\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=.]{16,})['\"]"), "medium"),
]

# Values that are obviously placeholders, not real secrets
PLACEHOLDERS = re.compile(
    r"(?i)(example|changeme|change_me|your[_-]?(api|secret|key|token|password)|xxxx|\*\*\*\*|<.*>|\$?\{.*\}|"
    r"dummy|placeholder|test123|password123|redacted|os\.environ|getenv|process\.env)")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random keys score high (> 4), words score low."""
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


HIGH_ENTROPY_CANDIDATE = re.compile(r"['\"=:]\s*['\"]?([A-Za-z0-9+/_=-]{32,})['\"]?")


def high_entropy_strings(line: str, threshold: float = 4.5) -> list[str]:
    found = []
    for m in HIGH_ENTROPY_CANDIDATE.finditer(line):
        token = m.group(1)
        if token.isdigit() or re.fullmatch(r"[a-f0-9]{32,64}", token):
            continue  # pure numbers and hex hashes (git commits, checksums) are noisy
        if shannon_entropy(token) >= threshold:
            found.append(token)
    return found
