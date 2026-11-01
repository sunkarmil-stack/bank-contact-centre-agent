"""Mint a LOCAL-ONLY dev token (refuses to run in prod).

    python -m scripts.issue_dev_token --persona reviewer
"""

from __future__ import annotations

import argparse

from ccagent.config import Settings
from ccagent.secrets import build_secret_provider
from ccagent.security.auth import DevTokenValidator, Role

PERSONAS = {
    "ivr": ("ivr-channel-svc", [Role.CHANNEL], {"channel": "ivr", "cust_auth_level": 1, "customer_ref": "SYN-C-1001"}),
    "agent": ("agent-001", [Role.AGENT], {"cust_auth_level": 1, "customer_ref": "SYN-C-1001"}),
    "reviewer": ("reviewer-007", [Role.REVIEWER], {}),
    "supervisor": ("supervisor-01", [Role.SUPERVISOR], {}),
    "auditor": ("auditor-01", [Role.AUDITOR], {}),
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--persona", choices=PERSONAS, required=True)
    ap.add_argument("--ttl", type=int, default=3600)
    a = ap.parse_args()
    s = Settings.from_env()
    sub, roles, extra = PERSONAS[a.persona]
    print(DevTokenValidator(s, build_secret_provider(s)).mint(sub, roles, ttl_s=a.ttl, **extra))
