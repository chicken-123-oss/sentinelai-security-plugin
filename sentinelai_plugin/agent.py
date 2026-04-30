from __future__ import annotations

import argparse
import json
import platform
import urllib.request
from typing import Any

from .sample_data import demo_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimal host-agent simulator for SentinelAI.")
    parser.add_argument("--api", default="http://127.0.0.1:8787")
    parser.add_argument("--token", default="dev-ingest-token")
    parser.add_argument("--agent-id", default="agent_local")
    parser.add_argument("--site-id", default="site_default")
    parser.add_argument("--send-demo-events", action="store_true")
    args = parser.parse_args(argv)

    post(
        args.api,
        "/api/v1/agents/check-in",
        args.token,
        {
            "agentId": args.agent_id,
            "status": "healthy",
            "policyVersion": "bundle-dev",
            "metadata": {"platform": platform.platform(), "python": platform.python_version()},
        },
    )

    if args.send_demo_events:
        for event in demo_events():
            event["agentId"] = args.agent_id
            event["siteId"] = args.site_id
            post(args.api, "/api/v1/events/ingest", args.token, event)

    print("host-agent check-in completed")
    return 0


def post(api_base: str, path: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        api_base.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())

