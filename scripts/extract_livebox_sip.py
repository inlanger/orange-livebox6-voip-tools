#!/usr/bin/env python3
"""Read-only extractor for Orange Spain Livebox 6 SIP credentials."""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


def request_json(base_url: str, path: str, user: str, password: str, timeout: float) -> Any:
    """GET JSON from the local Livebox API.

    The router ships with a self-signed certificate, so the script disables
    verification on purpose for this local management call.
    """

    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    request = Request(f"{base_url}{path}")
    request.add_header("Authorization", f"Basic {token}")
    request.add_header("Accept", "application/json")
    context = ssl._create_unverified_context()

    with urlopen(request, timeout=timeout, context=context) as response:
        body = response.read().decode("utf-8")
        return json.loads(body)


def choose_line(lines: list[dict[str, Any]], requested_line: str | None) -> dict[str, Any]:
    if requested_line:
        for line in lines:
            if line.get("name") == requested_line or line.get("directoryNumber") == requested_line:
                return line
        raise ValueError(f"Requested line {requested_line!r} was not found in Livebox response.")

    for line in lines:
        if line.get("name") and line.get("name") != "Unavailable":
            return line

    if lines:
        return lines[0]

    raise ValueError("The Livebox did not return any SIP lines.")


def write_private_file(target: Path, content: str) -> None:
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        if os.name == 'posix':
            os.fchmod(stream.fileno(), 0o600)
        stream.write(content)


def dump_json(target_dir: Path, name: str, payload: Any) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    write_private_file(target_dir / f"{name}.json", json.dumps(payload, indent=2, sort_keys=True) + "\n")


def build_env_map(line: dict[str, Any], sip: dict[str, Any]) -> dict[str, str]:
    number = str(line.get("directoryNumber") or line.get("name") or "")
    uri = str(line.get("uri") or "")
    domain = str(sip.get("userAgentDomain") or (uri.split("@", 1)[1] if "@" in uri else ""))
    registrar_host = str(sip.get("registrarServer") or domain)
    registrar_port = str(sip.get("registrarServerPort") or sip.get("proxyServerPort") or 5060)
    proxy_host = str(sip.get("proxyServer") or "")
    proxy_port = str(sip.get("proxyServerPort") or 5060)
    outbound_list = str(sip.get("outboundProxyServer") or "")
    outbound_host = outbound_list.split(",", 1)[0].strip()

    return {
        "ORANGE_PHONE_NUMBER": number,
        "ORANGE_SIP_URI": uri,
        "ORANGE_SIP_USERNAME": str(line.get("authUserName") or ""),
        "ORANGE_SIP_PASSWORD": str(line.get("authPassword") or ""),
        "ORANGE_SIP_DOMAIN": domain,
        "ORANGE_SIP_REGISTRAR_HOST": registrar_host,
        "ORANGE_SIP_REGISTRAR_PORT": registrar_port,
        "ORANGE_SIP_PROXY_HOST": proxy_host,
        "ORANGE_SIP_PROXY_PORT": proxy_port,
        "ORANGE_SIP_OUTBOUND_PROXY_HOST": outbound_host,
        "ORANGE_SIP_OUTBOUND_PROXY_LIST": outbound_list,
        "ORANGE_SIP_REGISTER_EXPIRES": "3600",
    }


def write_env_file(target: Path, values: dict[str, str]) -> None:
    lines = [f"{key}={value}" for key, value in values.items()]
    write_private_file(target, "\n".join(lines) + "\n")


def print_summary(line: dict[str, Any], sip: dict[str, Any], values: dict[str, str], show_secrets: bool = False) -> None:
    print("Livebox SIP extraction succeeded.\n")
    print("Selected line:")
    print(f"  name:             {line.get('name')}")
    print(f"  directoryNumber:  {line.get('directoryNumber')}")
    print(f"  uri:              {line.get('uri')}")
    print(f"  status:           {line.get('status')}")
    print()
    print("SIP routing:")
    print(f"  userAgentDomain:  {sip.get('userAgentDomain')}")
    print(f"  proxyServer:      {sip.get('proxyServer')}:{sip.get('proxyServerPort')}")
    print(f"  outboundProxy:    {sip.get('outboundProxyServer')}:{sip.get('outboundProxyServerPort')}")
    print()
    print("dotenv export:")
    for key, value in values.items():
        if key == "ORANGE_SIP_PASSWORD" and not show_secrets:
            value = "<redacted>"
        print(f"{key}={value}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.1.1", help="Livebox host or IP address.")
    parser.add_argument("--base-path", default="/API/1.0", help="Base API path. Defaults to /API/1.0.")
    parser.add_argument("--user", default="UsrAdmin", help="Livebox API username.")
    parser.add_argument(
        "--password",
        required=True,
        help="Livebox API password. On this model, the Wi-Fi key from the sticker worked.",
    )
    parser.add_argument("--line", help="Specific line name or directory number to extract.")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds.")
    parser.add_argument("--env-file", type=Path, help="Optional dotenv output path.")
    parser.add_argument("--show-secrets", action="store_true", help="Include the SIP password in terminal output.")
    parser.add_argument("--dump-dir", type=Path, help="Optional directory where raw JSON replies are stored.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = f"https://{args.host}{args.base_path}"

    try:
        voip = request_json(base_url, "/VoIP", args.user, args.password, args.timeout)
        sip = request_json(base_url, "/VoIP/SIP", args.user, args.password, args.timeout)
        lines = request_json(base_url, "/VoIP/SIP/Lines", args.user, args.password, args.timeout)
        selected_line = choose_line(lines, args.line)
        encoded_line = quote(str(selected_line.get("name") or selected_line.get("directoryNumber")), safe="")
        line_details = request_json(
            base_url,
            f"/VoIP/SIP/Lines/{encoded_line}",
            args.user,
            args.password,
            args.timeout,
        )
    except HTTPError as exc:
        print(f"HTTP error while talking to the Livebox API: {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except URLError as exc:
        print(f"Network error while talking to the Livebox API: {exc.reason}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.dump_dir:
        dump_json(args.dump_dir, "voip", voip)
        dump_json(args.dump_dir, "sip", sip)
        dump_json(args.dump_dir, "lines", lines)
        dump_json(args.dump_dir, "line", line_details)

    env_values = build_env_map(line_details, sip)
    print_summary(line_details, sip, env_values, show_secrets=args.show_secrets)

    if args.env_file:
        write_env_file(args.env_file, env_values)
        print(f"\nWrote dotenv output to {args.env_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
