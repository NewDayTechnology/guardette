import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]*-\d+")


def do_request(url, *args, timeout=30, **kwargs):
    print(f"Requesting {url}")
    response = requests.get(url, *args, timeout=timeout, **kwargs)
    if response.status_code != 200:
        message = f"Error with status code: {response.status_code}, Message: {response.text}"
        print(message)
        raise requests.HTTPError(message, response=response)
    return response.json()


def _headers(token, jira_host):
    return {
        "X-Guardette-Host": jira_host,
        "Authorization": token,
        "Accept": "application/json",
    }


def _output_dir():
    output_dir = Path(".guardette")
    output_dir.mkdir(exist_ok=True)
    return output_dir


def fetch_issue(token, jira_host, proxy_base_url, key):
    if not ISSUE_KEY.fullmatch(key):
        raise ValueError(f"Not a Jira issue key: {key!r}")
    issue = do_request(
        f"{proxy_base_url}/rest/api/3/issue/{key}",
        headers=_headers(token, jira_host),
        params={"fields": "*all", "expand": "renderedFields,changelog"},
    )
    (_output_dir() / "jira_issue_response.json").write_text(json.dumps(issue, indent=4))
    print(f"Retrieved issue: {issue.get('key', key)}")


def extended_apis(token, jira_host, proxy_base_url):
    """Routes outside the MVP; they return 404 unless the policy has include_extended_routes."""
    headers = _headers(token, jira_host)
    output_dir = _output_dir()

    do_request(f"{proxy_base_url}/rest/api/3/users/search", headers=headers)

    boards_response = do_request(f"{proxy_base_url}/rest/agile/1.0/board", headers=headers)
    (output_dir / "jira_boards_response.json").write_text(json.dumps(boards_response, indent=4))

    board_id = boards_response["values"][0]["id"]
    issues_response = do_request(
        f"{proxy_base_url}/rest/agile/1.0/board/{board_id}/issue?expand=renderedFields,transitions,changelog",
        headers=headers,
    )
    (output_dir / "jira_board_issues_response.json").write_text(json.dumps(issues_response, indent=4))

    print(f"Retrieved issues for board ID: {board_id}")
    print(f"Issues retrieved: {len(issues_response.get('issues', []))}")


def main():
    parser = argparse.ArgumentParser(description="Fetch Jira data through Guardette.")
    parser.add_argument("--key", required=True, help="Jira issue key to fetch, for example ABC-123")
    parser.add_argument(
        "--extended", action="store_true", help="Also call the users and board routes (needs extended routes)"
    )
    args = parser.parse_args()

    load_dotenv()
    # Guardette injects the Jira credentials; the client only presents CLIENT_SECRET.
    token = os.getenv("PROXY_TOKEN") or os.getenv("CLIENT_SECRET")
    proxy_base_url = os.getenv("PROXY_BASE_URL", "http://localhost:8000")
    jira_host = os.getenv("JIRA_HOST")

    if token is None:
        print("PROXY_TOKEN or CLIENT_SECRET environment variable is not set.")
        sys.exit(1)

    if jira_host is None:
        print("JIRA_HOST environment variable is not set.")
        sys.exit(1)

    fetch_issue(token, jira_host, proxy_base_url, args.key)
    if args.extended:
        extended_apis(token, jira_host, proxy_base_url)


if __name__ == "__main__":
    main()
