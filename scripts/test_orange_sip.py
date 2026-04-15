#!/usr/bin/env python3
"""Raw SIP test client for Orange Spain.

This is intentionally a signaling-first tool:
- mode=register verifies SIP registration only
- mode=ring-once places a short call and sends CANCEL on the first 180 Ringing

It is useful for validating credentials and Orange-side signaling, but it is
not a production softphone or PBX.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import re
import socket
import sys
import time
from pathlib import Path
from typing import Iterable


def load_env_file(path: Path) -> None:
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def env_or_arg(value: str | None, env_name: str) -> str:
    resolved = value or os.environ.get(env_name)
    if not resolved:
        raise ValueError(f"Missing required value: {env_name}")
    return resolved


def md5(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def random_hex(length: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(length))


def sanitize_sip(message: str) -> str:
    message = re.sub(r"^(Authorization|Proxy-Authorization): .+$", r"\1: <redacted>", message, flags=re.M)
    return message


def log_sip(prefix: str, message: str) -> None:
    print(f"\n--- {prefix} ---")
    print(sanitize_sip(message))


def recv_sip(sock: socket.socket, timeout: float) -> str | None:
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(65535)
    except socket.timeout:
        print("\n--- TIMEOUT ---")
        return None

    decoded = data.decode("utf-8", errors="replace")
    log_sip(f"Response from {addr[0]}:{addr[1]}", decoded)
    return decoded


def parse_status_code(message: str) -> int:
    match = re.search(r"^SIP/2.0\s+(\d+)", message, re.M)
    if not match:
        raise ValueError("Could not parse SIP response status code.")
    return int(match.group(1))


def parse_header(message: str, header_name: str) -> str | None:
    match = re.search(rf"^{re.escape(header_name)}:\s*(.+)$", message, re.M)
    return match.group(1).strip() if match else None


def parse_to_tag(message: str) -> str | None:
    match = re.search(r"^To:\s*.*;tag=([^\s;]+)", message, re.M)
    return match.group(1) if match else None


def parse_digest_challenge(message: str) -> tuple[str, dict[str, str]] | tuple[None, None]:
    match = re.search(r"^(WWW-Authenticate|Proxy-Authenticate):\s*Digest\s+(.+)$", message, re.M)
    if not match:
        return None, None

    header_name = match.group(1)
    params: dict[str, str] = {}
    for part in re.split(r",\s*(?=\w+=)", match.group(2)):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        params[key.strip()] = value.strip().strip('"')
    return header_name, params


def build_digest_authorization(
    header_name: str,
    params: dict[str, str],
    username: str,
    password: str,
    method: str,
    uri: str,
) -> tuple[str, str]:
    realm = params["realm"]
    nonce = params["nonce"]
    qop = params.get("qop", "")
    algorithm = params.get("algorithm", "MD5")
    opaque = params.get("opaque")
    cnonce = random_hex(16)
    nc = "00000001"

    ha1 = md5(f"{username}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    if qop:
        qop = qop.split(",")[0].strip()
        response = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        response = md5(f"{ha1}:{nonce}:{ha2}")

    fields = [
        f'Digest username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f'algorithm={algorithm}',
    ]
    if opaque:
        fields.append(f'opaque="{opaque}"')
    if qop:
        fields.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])

    auth_header_name = "Proxy-Authorization" if header_name == "Proxy-Authenticate" else "Authorization"
    return auth_header_name, ", ".join(fields)


def make_sdp(local_ip: str, rtp_port: int) -> str:
    # This is enough for signaling validation, but not a full media stack.
    return "\r\n".join(
        [
            "v=0",
            f"o=- {int(time.time())} {int(time.time())} IN IP4 {local_ip}",
            "s=OrangeSIPTest",
            f"c=IN IP4 {local_ip}",
            "t=0 0",
            f"m=audio {rtp_port} RTP/AVP 8 0 101",
            "a=rtpmap:8 PCMA/8000",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:101 telephone-event/8000",
            "a=fmtp:101 0-16",
            "a=ptime:20",
            "a=sendrecv",
            "",
        ]
    )


def join_headers(headers: Iterable[str], body: str = "") -> str:
    return "\r\n".join(headers) + "\r\n\r\n" + body


def build_register(
    *,
    domain: str,
    from_number: str,
    local_ip: str,
    local_port: int,
    call_id: str,
    from_tag: str,
    branch: str,
    cseq: int,
    expires: int,
    auth_header: tuple[str, str] | None = None,
) -> str:
    uri = f"sip:{domain}"
    headers = [
        f"REGISTER {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{from_number}@{domain}>",
        f"From: <sip:{from_number}@{domain}>;tag={from_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: <sip:{from_number}@{local_ip}:{local_port};transport=udp>;expires={expires}",
        f"Expires: {expires}",
        "User-Agent: OrangeLivebox6VoipTools/0.1",
        "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, INFO, REGISTER",
    ]
    if auth_header:
        headers.append(f"{auth_header[0]}: {auth_header[1]}")
    headers.append("Content-Length: 0")
    return join_headers(headers)


def build_invite(
    *,
    destination: str,
    domain: str,
    from_number: str,
    local_ip: str,
    local_port: int,
    call_id: str,
    from_tag: str,
    branch: str,
    cseq: int,
    route: str | None,
    auth_header: tuple[str, str] | None,
    body: str,
) -> str:
    request_uri = f"sip:{destination}@{domain}"
    headers = [
        f"INVITE {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{destination}@{domain}>",
        f"From: <sip:{from_number}@{domain}>;tag={from_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} INVITE",
        f"Contact: <sip:{from_number}@{local_ip}:{local_port};transport=udp>",
        "User-Agent: OrangeLivebox6VoipTools/0.1",
        "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, INFO, REGISTER",
        f"P-Preferred-Identity: <sip:{from_number}@{domain}>",
    ]
    if route:
        headers.append(f"Route: {route}")
    if auth_header:
        headers.append(f"{auth_header[0]}: {auth_header[1]}")
    headers.extend(
        [
            "Content-Type: application/sdp",
            f"Content-Length: {len(body.encode('utf-8'))}",
        ]
    )
    return join_headers(headers, body)


def build_cancel(
    *,
    destination: str,
    domain: str,
    from_number: str,
    local_ip: str,
    local_port: int,
    call_id: str,
    from_tag: str,
    branch: str,
    cseq: int,
    to_tag: str | None,
    route: str | None,
) -> str:
    request_uri = f"sip:{destination}@{domain}"
    headers = [
        f"CANCEL {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{destination}@{domain}>" + (f";tag={to_tag}" if to_tag else ""),
        f"From: <sip:{from_number}@{domain}>;tag={from_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} CANCEL",
        "User-Agent: OrangeLivebox6VoipTools/0.1",
    ]
    if route:
        headers.append(f"Route: {route}")
    headers.append("Content-Length: 0")
    return join_headers(headers)


def build_ack(
    *,
    destination: str,
    domain: str,
    from_number: str,
    local_ip: str,
    local_port: int,
    call_id: str,
    from_tag: str,
    branch: str,
    cseq: int,
    to_tag: str | None,
    route: str | None,
) -> str:
    request_uri = f"sip:{destination}@{domain}"
    headers = [
        f"ACK {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{destination}@{domain}>" + (f";tag={to_tag}" if to_tag else ""),
        f"From: <sip:{from_number}@{domain}>;tag={from_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} ACK",
        "User-Agent: OrangeLivebox6VoipTools/0.1",
    ]
    if route:
        headers.append(f"Route: {route}")
    headers.append("Content-Length: 0")
    return join_headers(headers)


def perform_register(
    sock: socket.socket,
    *,
    username: str,
    password: str,
    from_number: str,
    domain: str,
    expires: int,
    timeout: float,
) -> str | None:
    local_ip, local_port = sock.getsockname()
    call_id = f"{int(time.time())}-{random.randint(1000, 9999)}@register"
    from_tag = random_hex(8)

    message = build_register(
        domain=domain,
        from_number=from_number,
        local_ip=local_ip,
        local_port=local_port,
        call_id=call_id,
        from_tag=from_tag,
        branch="z9hG4bK" + random_hex(16),
        cseq=1,
        expires=expires,
    )
    log_sip("REGISTER 1", message)
    sock.send(message.encode("utf-8"))
    response = recv_sip(sock, timeout)
    if not response:
        raise RuntimeError("Timed out waiting for REGISTER challenge.")

    status = parse_status_code(response)
    if status == 423:
        raise RuntimeError("Orange replied 423 Interval Too Brief. Use --expires 3600.")
    if status != 401:
        raise RuntimeError(f"Expected 401 on first REGISTER, got {status}.")

    header_name, params = parse_digest_challenge(response)
    if not header_name or not params:
        raise RuntimeError("Could not parse REGISTER digest challenge.")

    auth = build_digest_authorization(header_name, params, username, password, "REGISTER", f"sip:{domain}")
    message = build_register(
        domain=domain,
        from_number=from_number,
        local_ip=local_ip,
        local_port=local_port,
        call_id=call_id,
        from_tag=from_tag,
        branch="z9hG4bK" + random_hex(16),
        cseq=2,
        expires=expires,
        auth_header=auth,
    )
    log_sip("REGISTER 2", message)
    sock.send(message.encode("utf-8"))
    response = recv_sip(sock, timeout)
    if not response:
        raise RuntimeError("Timed out waiting for authenticated REGISTER.")

    status = parse_status_code(response)
    if status != 200:
        raise RuntimeError(f"REGISTER failed with status {status}.")

    return parse_header(response, "Service-Route")


def perform_ring_once(
    sock: socket.socket,
    *,
    username: str,
    password: str,
    from_number: str,
    destination: str,
    domain: str,
    route: str | None,
    timeout: float,
) -> None:
    local_ip, local_port = sock.getsockname()
    rtp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp_socket.bind(("", 0))
    rtp_port = rtp_socket.getsockname()[1]
    call_id = f"{int(time.time())}-{random.randint(1000, 9999)}@invite"
    from_tag = random_hex(8)
    body = make_sdp(local_ip, rtp_port)
    request_uri = f"sip:{destination}@{domain}"
    cseq = 1
    branch = "z9hG4bK" + random_hex(16)

    message = build_invite(
        destination=destination,
        domain=domain,
        from_number=from_number,
        local_ip=local_ip,
        local_port=local_port,
        call_id=call_id,
        from_tag=from_tag,
        branch=branch,
        cseq=cseq,
        route=route,
        auth_header=None,
        body=body,
    )
    log_sip("INVITE 1", message)
    sock.send(message.encode("utf-8"))

    to_tag: str | None = None
    for _ in range(16):
        response = recv_sip(sock, timeout)
        if not response:
            raise RuntimeError("Timed out waiting for INVITE responses.")

        status = parse_status_code(response)
        if parse_to_tag(response):
            to_tag = parse_to_tag(response)

        if status in (100, 183):
            # 183 is normal on Orange before the phone starts ringing.
            continue

        if status in (401, 407):
            header_name, params = parse_digest_challenge(response)
            if not header_name or not params:
                raise RuntimeError("Could not parse INVITE digest challenge.")

            cseq = 2
            branch = "z9hG4bK" + random_hex(16)
            auth = build_digest_authorization(
                header_name,
                params,
                username,
                password,
                "INVITE",
                request_uri,
            )
            message = build_invite(
                destination=destination,
                domain=domain,
                from_number=from_number,
                local_ip=local_ip,
                local_port=local_port,
                call_id=call_id,
                from_tag=from_tag,
                branch=branch,
                cseq=cseq,
                route=route,
                auth_header=auth,
                body=body,
            )
            log_sip("INVITE 2", message)
            sock.send(message.encode("utf-8"))
            continue

        if status == 180:
            message = build_cancel(
                destination=destination,
                domain=domain,
                from_number=from_number,
                local_ip=local_ip,
                local_port=local_port,
                call_id=call_id,
                from_tag=from_tag,
                branch=branch,
                cseq=cseq,
                to_tag=to_tag,
                route=route,
            )
            log_sip("CANCEL", message)
            sock.send(message.encode("utf-8"))

            saw_487 = False
            for _ in range(4):
                cancel_response = recv_sip(sock, timeout)
                if not cancel_response:
                    break
                cancel_status = parse_status_code(cancel_response)
                if cancel_status == 487:
                    saw_487 = True
                    ack = build_ack(
                        destination=destination,
                        domain=domain,
                        from_number=from_number,
                        local_ip=local_ip,
                        local_port=local_port,
                        call_id=call_id,
                        from_tag=from_tag,
                        branch="z9hG4bK" + random_hex(16),
                        cseq=cseq,
                        to_tag=parse_to_tag(cancel_response) or to_tag,
                        route=route,
                    )
                    log_sip("ACK", ack)
                    sock.send(ack.encode("utf-8"))
                    break

            if not saw_487:
                raise RuntimeError("Sent CANCEL, but never saw 487 Request Terminated.")
            print("\nCall reached 180 Ringing and was cancelled cleanly.")
            return

        if status >= 200:
            raise RuntimeError(
                f"INVITE reached final status {status} before ring/cancel logic completed."
            )

    raise RuntimeError("Did not reach 180 Ringing in time.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, help="Optional dotenv file like examples/orange_voip.env.example.")
    parser.add_argument("--mode", choices=["register", "ring-once"], default="register")
    parser.add_argument("--livebox-host", help="Not used by this script directly, but kept for dotenv symmetry.")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--from-number")
    parser.add_argument("--destination", help="Target phone number for mode=ring-once.")
    parser.add_argument("--domain")
    parser.add_argument("--proxy-host")
    parser.add_argument("--proxy-port", type=int)
    parser.add_argument("--expires", type=int)
    parser.add_argument("--timeout", type=float, default=8.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.env_file:
        load_env_file(args.env_file)

    try:
        username = env_or_arg(args.username, "ORANGE_SIP_USERNAME")
        password = env_or_arg(args.password, "ORANGE_SIP_PASSWORD")
        from_number = env_or_arg(args.from_number, "ORANGE_PHONE_NUMBER")
        domain = env_or_arg(args.domain, "ORANGE_SIP_DOMAIN")
        proxy_host = env_or_arg(args.proxy_host, "ORANGE_SIP_PROXY_HOST")
        proxy_port = int(args.proxy_port or os.environ.get("ORANGE_SIP_PROXY_PORT", "5060"))
        expires = int(args.expires or os.environ.get("ORANGE_SIP_REGISTER_EXPIRES", "3600"))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.mode == "ring-once" and not args.destination:
        print("--destination is required for mode=ring-once", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((proxy_host, proxy_port))
    print(f"Connected UDP socket to {proxy_host}:{proxy_port} from {sock.getsockname()[0]}:{sock.getsockname()[1]}")

    try:
        route = perform_register(
            sock,
            username=username,
            password=password,
            from_number=from_number,
            domain=domain,
            expires=expires,
            timeout=args.timeout,
        )
        print(f"\nREGISTER succeeded. Service-Route: {route}")

        if args.mode == "register":
            return 0

        perform_ring_once(
            sock,
            username=username,
            password=password,
            from_number=from_number,
            destination=args.destination,
            domain=domain,
            route=route,
            timeout=args.timeout,
        )
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
