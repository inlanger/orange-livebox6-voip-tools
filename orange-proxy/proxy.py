#!/usr/bin/env python3

import argparse
import dataclasses
import hashlib
import logging
import os
import random
import re
import select
import socket
import sys
import time
import uuid
from pathlib import Path
from typing import Callable, Optional


LOG = logging.getLogger("orange-sip-proxy")
MAX_PACKET = 65535
ALLOWED_METHODS = "INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, INFO, REGISTER"


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    return int(value)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def md5(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def new_branch() -> str:
    return "z9hG4bK" + "".join(random.choice("0123456789abcdef") for _ in range(16))


def new_tag(length: int = 8) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(length))


def new_call_id(suffix: str) -> str:
    return f"{uuid.uuid4().hex}@{suffix}"


def normalize_header_name(name: str) -> str:
    return name.strip().lower()


@dataclasses.dataclass
class SIPMessage:
    start_line: str
    headers: list[tuple[str, str]]
    body: bytes

    @property
    def is_response(self) -> bool:
        return self.start_line.startswith("SIP/2.0 ")

    @property
    def method(self) -> str:
        return self.start_line.split(" ", 1)[0]

    @property
    def request_uri(self) -> str:
        parts = self.start_line.split(" ", 2)
        return parts[1] if len(parts) > 1 else ""

    @property
    def status_code(self) -> int:
        parts = self.start_line.split(" ", 2)
        return int(parts[1]) if len(parts) > 1 else 0

    @property
    def reason(self) -> str:
        parts = self.start_line.split(" ", 2)
        return parts[2] if len(parts) > 2 else ""

    def get(self, name: str) -> Optional[str]:
        needle = normalize_header_name(name)
        for key, value in self.headers:
            if normalize_header_name(key) == needle:
                return value
        return None

    def get_all(self, name: str) -> list[str]:
        needle = normalize_header_name(name)
        return [value for key, value in self.headers if normalize_header_name(key) == needle]

    def to_bytes(self) -> bytes:
        lines = [self.start_line]
        for key, value in self.headers:
            lines.append(f"{key}: {value}")
        lines.append("")
        head = "\r\n".join(lines).encode()
        return head + b"\r\n" + self.body


def parse_sip_message(data: bytes) -> SIPMessage:
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = data.partition(b"\n\n")
    header_text = head.decode(errors="replace").replace("\r\n", "\n").split("\n")
    if not header_text or not header_text[0]:
        raise ValueError("empty SIP packet")
    start_line = header_text[0].strip()
    headers: list[tuple[str, str]] = []
    current_name: Optional[str] = None
    current_value: Optional[str] = None
    for raw_line in header_text[1:]:
        if not raw_line:
            continue
        if raw_line[:1] in (" ", "\t") and current_name is not None and current_value is not None:
            current_value += " " + raw_line.strip()
            continue
        if current_name is not None and current_value is not None:
            headers.append((current_name, current_value))
        if ":" not in raw_line:
            continue
        current_name, current_value = raw_line.split(":", 1)
        current_name = current_name.strip()
        current_value = current_value.strip()
    if current_name is not None and current_value is not None:
        headers.append((current_name, current_value))
    content_length = 0
    for key, value in headers:
        if normalize_header_name(key) == "content-length":
            try:
                content_length = int(value.strip())
            except ValueError:
                content_length = 0
            break
    if content_length:
        body = body[:content_length]
    else:
        body = b""
    return SIPMessage(start_line=start_line, headers=headers, body=body)


def extract_uri(value: str) -> str:
    if not value:
        return ""
    match = re.search(r"<([^>]+)>", value)
    if match:
        return match.group(1).strip()
    return value.split(";", 1)[0].strip()


def extract_tag(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    match = re.search(r"(?:^|;)\s*tag=([^;\s>]+)", value)
    return match.group(1) if match else None


def with_tag(value: str, tag: str) -> str:
    if extract_tag(value):
        return value
    return f"{value};tag={tag}"


def parse_cseq(value: Optional[str]) -> tuple[int, str]:
    if not value:
        return 0, ""
    parts = value.strip().split()
    if len(parts) < 2:
        return 0, ""
    return int(parts[0]), parts[1].upper()


def parse_uri(uri: str) -> tuple[str, str, int]:
    cleaned = extract_uri(uri)
    if cleaned.startswith("sip:"):
        cleaned = cleaned[4:]
    elif cleaned.startswith("sips:"):
        cleaned = cleaned[5:]
    cleaned = cleaned.split(";", 1)[0]
    user = ""
    host_port = cleaned
    if "@" in cleaned:
        user, host_port = cleaned.split("@", 1)
    if host_port.startswith("[") and "]" in host_port:
        host, rest = host_port[1:].split("]", 1)
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 5060
        return user, host, port
    if ":" in host_port and host_port.count(":") == 1:
        host, port_raw = host_port.rsplit(":", 1)
        if port_raw.isdigit():
            return user, host, int(port_raw)
    return user, host_port, 5060


def redact_header_value(name: str, value: str) -> str:
    lowered = normalize_header_name(name)
    if lowered in {"authorization", "proxy-authorization"}:
        return "<redacted>"
    return value


def format_sip_message(message: SIPMessage) -> str:
    lines = [message.start_line]
    for key, value in message.headers:
        lines.append(f"{key}: {redact_header_value(key, value)}")
    lines.append("")
    body = message.body.decode(errors="replace") if message.body else ""
    if body:
        lines.append(body)
    return "\n".join(lines).strip()


def identity_headers(message: SIPMessage) -> dict[str, str]:
    interesting = (
        "From",
        "To",
        "Contact",
        "P-Asserted-Identity",
        "P-Preferred-Identity",
        "Remote-Party-ID",
        "Privacy",
        "Diversion",
        "History-Info",
    )
    result: dict[str, str] = {}
    for header in interesting:
        value = message.get(header)
        if value:
            result[header] = redact_header_value(header, value)
    return result


def response_headers_from_request(
    request: SIPMessage,
    to_value: str,
    body: bytes = b"",
    extra_headers: Optional[list[tuple[str, str]]] = None,
) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for via in request.get_all("Via"):
        headers.append(("Via", via))
    headers.append(("To", to_value))
    from_value = request.get("From")
    if from_value:
        headers.append(("From", from_value))
    call_id = request.get("Call-ID")
    if call_id:
        headers.append(("Call-ID", call_id))
    cseq = request.get("CSeq")
    if cseq:
        headers.append(("CSeq", cseq))
    if extra_headers:
        headers.extend(extra_headers)
    headers.append(("Content-Length", str(len(body))))
    return headers


def build_response(
    request: SIPMessage,
    code: int,
    reason: str,
    to_value: str,
    body: bytes = b"",
    extra_headers: Optional[list[tuple[str, str]]] = None,
) -> bytes:
    message = SIPMessage(
        start_line=f"SIP/2.0 {code} {reason}",
        headers=response_headers_from_request(request, to_value, body=body, extra_headers=extra_headers),
        body=body,
    )
    return message.to_bytes()


def digest_challenge(response: SIPMessage) -> tuple[Optional[str], Optional[dict[str, str]]]:
    for header_name in ("WWW-Authenticate", "Proxy-Authenticate"):
        value = response.get(header_name)
        if not value:
            continue
        match = re.match(r"Digest\s+(.+)$", value, re.IGNORECASE)
        if not match:
            continue
        params: dict[str, str] = {}
        for part in re.split(r",\s*(?=\w+=)", match.group(1)):
            if "=" not in part:
                continue
            key, raw_value = part.split("=", 1)
            params[key.strip()] = raw_value.strip().strip('"')
        return header_name, params
    return None, None


def build_digest_auth(
    challenge_header: str,
    params: dict[str, str],
    method: str,
    uri: str,
    username: str,
    password: str,
) -> tuple[str, str]:
    realm = params["realm"]
    nonce = params["nonce"]
    qop = params.get("qop", "")
    algorithm = params.get("algorithm", "MD5")
    opaque = params.get("opaque")
    cnonce = "".join(random.choice("0123456789abcdef") for _ in range(16))
    nc = "00000001"
    ha1 = md5(f"{username}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    if qop:
        qop = qop.split(",")[0].strip()
        response = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        response = md5(f"{ha1}:{nonce}:{ha2}")
    parts = [
        f'Digest username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f"algorithm={algorithm}",
    ]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    if qop:
        parts.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])
    header_name = "Proxy-Authorization" if challenge_header.lower() == "proxy-authenticate" else "Authorization"
    return header_name, ", ".join(parts)


def parse_service_route(response: SIPMessage) -> Optional[str]:
    value = response.get("Service-Route")
    if not value:
        return None
    match = re.search(r"(<[^>]+>)", value)
    return match.group(1) if match else None


def parse_expires(response: SIPMessage, fallback: int) -> int:
    for contact in response.get_all("Contact"):
        match = re.search(r"(?:^|;)\s*expires=(\d+)", contact)
        if match:
            return int(match.group(1))
    expires = response.get("Expires")
    if expires and expires.isdigit():
        return int(expires)
    return fallback


def filter_headers(message: SIPMessage, allowed: set[str]) -> list[tuple[str, str]]:
    picked: list[tuple[str, str]] = []
    allowed_lower = {item.lower() for item in allowed}
    for key, value in message.headers:
        if normalize_header_name(key) in allowed_lower:
            picked.append((key, value))
    return picked


def request_destination(
    request_uri: str,
    route_headers: list[str],
    default_host: Optional[str] = None,
    default_port: int = 5060,
) -> tuple[str, int]:
    target = route_headers[0] if route_headers else request_uri
    _, host, port = parse_uri(target)
    if host:
        return host, port
    if default_host:
        return default_host, default_port
    raise ValueError(f"unable to resolve destination from {target!r}")


@dataclasses.dataclass
class BridgeConfig:
    auth_username: str
    password: str
    from_number: str
    domain: str
    proxy_host: str
    proxy_port: int
    register_expires: int
    bind_host: str
    bind_port: int
    downstream_port: int
    register_contact_port: int
    upstream_host: str
    upstream_port: int
    public_host: str
    register_margin: int
    invite_timeout: int
    user_agent: str
    trace_sip: bool
    max_calls: int = 0

    def __post_init__(self) -> None:
        if self.max_calls < 0:
            raise ValueError("ORANGE_PROXY_MAX_CALLS must be zero or positive")

    @classmethod
    def from_env(cls) -> "BridgeConfig":
        auth_username = os.environ.get("ORANGE_SIP_USERNAME", os.environ.get("ORANGE_AUTH_USERNAME", "")).strip()
        password = os.environ.get("ORANGE_SIP_PASSWORD", os.environ.get("ORANGE_PASSWORD", "")).strip()
        from_number = os.environ.get("ORANGE_PHONE_NUMBER", os.environ.get("ORANGE_FROM_NUMBER", "")).strip()
        if not auth_username or not password or not from_number:
            raise RuntimeError(
                "ORANGE_SIP_USERNAME, ORANGE_SIP_PASSWORD, and ORANGE_PHONE_NUMBER are required"
            )
        downstream_port = env_int("ORANGE_PROXY_DOWNSTREAM_PORT", 5070)
        return cls(
            auth_username=auth_username,
            password=password,
            from_number=from_number,
            domain=os.environ.get("ORANGE_SIP_DOMAIN", os.environ.get("ORANGE_DOMAIN", "sip.orange.es")).strip(),
            proxy_host=os.environ.get("ORANGE_SIP_PROXY_HOST", os.environ.get("ORANGE_PROXY_HOST", "proxy2.sip.orange.es")).strip(),
            proxy_port=int(os.environ.get("ORANGE_SIP_PROXY_PORT") or os.environ.get("ORANGE_PROXY_PORT") or 5060),
            register_expires=int(os.environ.get("ORANGE_SIP_REGISTER_EXPIRES") or os.environ.get("ORANGE_REGISTER_EXPIRES") or 3600),
            bind_host=os.environ.get("ORANGE_PROXY_BIND_HOST", "0.0.0.0").strip(),
            bind_port=env_int("ORANGE_PROXY_BIND_PORT", 5064),
            downstream_port=downstream_port,
            register_contact_port=env_int("ORANGE_REGISTER_CONTACT_PORT", downstream_port),
            upstream_host=os.environ.get("ORANGE_PROXY_UPSTREAM_HOST", "127.0.0.1").strip(),
            upstream_port=env_int("ORANGE_PROXY_UPSTREAM_PORT", 5060),
            public_host=os.environ.get("ORANGE_PROXY_PUBLIC_HOST", "").strip(),
            register_margin=env_int("ORANGE_REGISTER_MARGIN", 120),
            invite_timeout=env_int("ORANGE_PROXY_INVITE_TIMEOUT", 60),
            user_agent=os.environ.get("ORANGE_PROXY_USER_AGENT", "OrangeBridge/0.1").strip(),
            trace_sip=env_bool("ORANGE_PROXY_TRACE_SIP", False),
            max_calls=env_int("ORANGE_PROXY_MAX_CALLS", 0),
        )


@dataclasses.dataclass
class RegisterState:
    service_route: Optional[str] = None
    valid_until: float = 0.0


@dataclasses.dataclass
class RegisterTransaction:
    call_id: str
    from_tag: str
    cseq: int = 0
    payload: bytes = b""
    deadline: float = 0.0
    next_send: float = 0.0
    retry_interval: float = 0.5


@dataclasses.dataclass
class CallSession:
    upstream_request: SIPMessage
    upstream_addr: tuple[str, int]
    upstream_tag: str
    upstream_remote_target: str
    upstream_next_cseq: int
    called_number: str
    downstream_call_id: str
    downstream_from_tag: str
    downstream_invite_cseq: int = 1
    downstream_last_branch: str = ""
    downstream_to_tag: Optional[str] = None
    downstream_contact_uri: Optional[str] = None
    downstream_route_headers: list[str] = dataclasses.field(default_factory=list)
    answered: bool = False
    cancelled: bool = False
    waiting_bye_response: bool = False
    sent_bye_upstream: bool = False
    sent_bye_downstream: bool = False
    finished: bool = False
    auth_attempts: int = 0
    started_at: float = dataclasses.field(default_factory=time.time)

    @property
    def upstream_call_id(self) -> str:
        return self.upstream_request.get("Call-ID") or ""

    @property
    def upstream_from(self) -> str:
        return self.upstream_request.get("From") or ""

    @property
    def upstream_to(self) -> str:
        return self.upstream_request.get("To") or ""

    @property
    def upstream_cseq(self) -> int:
        return parse_cseq(self.upstream_request.get("CSeq"))[0]


@dataclasses.dataclass
class InboundCallSession:
    downstream_request: SIPMessage
    downstream_addr: tuple[str, int]
    downstream_to_tag: str
    called_number: str
    upstream_call_id: str
    upstream_request_uri: str
    upstream_from: str
    upstream_to: str
    upstream_invite_cseq: int
    upstream_next_cseq: int
    upstream_invite_branch: str
    upstream_remote_target: str
    upstream_to_tag: Optional[str] = None
    upstream_route_headers: list[str] = dataclasses.field(default_factory=list)
    answered: bool = False
    downstream_cancelled: bool = False
    finished: bool = False
    waiting_bye_response: bool = False

    @property
    def downstream_call_id(self) -> str:
        return self.downstream_request.get("Call-ID") or ""


# RFC 3261 UDP transaction timers. Call/dialog lifetime is independent of these.
SIP_T1 = 0.5
SIP_T2 = 4.0
SIP_T4 = 5.0
SIP_TRANSACTION_TIMEOUT = 64 * SIP_T1


def transaction_key(sock, message: SIPMessage, method: Optional[str] = None) -> tuple:
    via = message.get("Via") or ""
    branch = re.search(r"(?:^|;)\s*branch=([^;\s]+)", via)
    cseq, cseq_method = parse_cseq(message.get("CSeq"))
    sent_by = via.split(";", 1)[0].lower()
    return (sock, sent_by, branch.group(1) if branch else "", message.get("Call-ID"), cseq, method or cseq_method)


@dataclasses.dataclass
class ClientTransaction:
    request: SIPMessage
    payload: bytes
    sock: socket.socket
    addr: Optional[tuple[str, int]]
    expires: float
    retry_at: Optional[float]
    on_response: Optional[Callable[[SIPMessage], None]] = None
    interval: float = SIP_T1
    provisional: bool = False
    response: Optional[SIPMessage] = None
    ack: Optional[bytes] = None
    pending_cancel: Optional[bytes] = None
    timed_out: bool = False


@dataclasses.dataclass
class ServerTransaction:
    response: SIPMessage
    payload: bytes
    sock: socket.socket
    addr: Optional[tuple[str, int]]
    expires: float
    retry_at: Optional[float]
    on_ack_timeout: Optional[Callable[[], None]] = None
    interval: float = SIP_T1


class OrangeSIPBridge:
    def __init__(self, config: BridgeConfig) -> None:
        self.config = config
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((config.bind_host, config.bind_port))
        self.sock.setblocking(False)
        self.downstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.downstream_sock.bind((config.bind_host, config.downstream_port))
        self.downstream_sock.connect((config.proxy_host, config.proxy_port))
        self.downstream_sock.setblocking(False)
        self.register_state = RegisterState()
        self.register_transaction: RegisterTransaction | None = None
        self.register_retry_at = 0.0
        self.client_transactions: dict[tuple, ClientTransaction] = {}
        self.server_transactions: dict[tuple, ServerTransaction] = {}
        self.sessions: dict[tuple, CallSession | InboundCallSession] = {}
        self.advertised_host = config.public_host or self._discover_advertised_host()

    @staticmethod
    def _send_raw(sock, payload: bytes, addr: Optional[tuple[str, int]]) -> None:
        if addr is None:
            sock.send(payload)
        else:
            sock.sendto(payload, addr)

    def send_upstream(self, payload: bytes, addr: tuple[str, int], **kwargs) -> None:
        self.send_sip(self.sock, payload, addr, **kwargs)

    def send_downstream(self, payload: bytes, **kwargs) -> None:
        self.send_sip(self.downstream_sock, payload, None, **kwargs)

    def send_sip(self, sock, payload: bytes, addr, on_response=None, on_ack_timeout=None) -> None:
        message = parse_sip_message(payload)
        _, method = parse_cseq(message.get("CSeq"))
        now = time.monotonic()
        key = transaction_key(sock, message)
        if message.is_response and method in {"INVITE", "BYE", "CANCEL"}:
            final_invite = method == "INVITE" and message.status_code >= 200
            self.server_transactions[key] = ServerTransaction(
                message, payload, sock, addr,
                now + (SIP_TRANSACTION_TIMEOUT if message.status_code >= 200 else self.config.invite_timeout + SIP_TRANSACTION_TIMEOUT),
                now + SIP_T1 if final_invite else None, on_ack_timeout,
            )
        elif not message.is_response and method in {"INVITE", "BYE", "CANCEL"}:
            if method == "CANCEL":
                invite = self.client_transactions.get(transaction_key(sock, message, "INVITE"))
                if invite is None or invite.response is not None:
                    return
                if not invite.provisional:
                    invite.pending_cancel = payload
                    return  # RFC 3261 9.1: wait for a provisional response.
                invite.expires = min(invite.expires, now + SIP_TRANSACTION_TIMEOUT)
            if key in self.client_transactions:
                return
            self.client_transactions[key] = ClientTransaction(
                message, payload, sock, addr, now + SIP_TRANSACTION_TIMEOUT, now + SIP_T1, on_response,
            )
        elif not message.is_response and method == "ACK":
            for tx in self.client_transactions.values():
                if (tx.sock is sock and tx.request.get("Call-ID") == message.get("Call-ID")
                        and parse_cseq(tx.request.get("CSeq")) == (parse_cseq(message.get("CSeq"))[0], "INVITE")
                        and tx.response is not None and tx.response.get("To") == message.get("To")):
                    tx.ack = payload
                    break
        self._send_raw(sock, payload, addr)

    def tick_transactions(self) -> None:
        now = time.monotonic()
        for key, tx in list(self.client_transactions.items()):
            if now >= tx.expires:
                if tx.response is not None or tx.timed_out:
                    del self.client_transactions[key]
                    continue
                LOG.warning("SIP transaction timed out call_id=%s cseq=%s", tx.request.get("Call-ID"), tx.request.get("CSeq"))
                tx.timed_out = True
                tx.retry_at = None
                tx.expires = now + SIP_TRANSACTION_TIMEOUT
                if tx.on_response:
                    response = parse_sip_message(build_response(tx.request, 408, "Request Timeout", tx.request.get("To") or ""))
                    tx.on_response(response)
                continue
            if tx.retry_at is not None and now >= tx.retry_at:
                self._send_raw(tx.sock, tx.payload, tx.addr)
                # Timer A doubles; non-INVITE Timer E is capped at T2.
                tx.interval = tx.interval * 2 if tx.request.method == "INVITE" else min(SIP_T2, tx.interval * 2)
                tx.retry_at = now + tx.interval
                LOG.info("retransmitting SIP request call_id=%s cseq=%s", tx.request.get("Call-ID"), tx.request.get("CSeq"))
        for key, tx in list(self.server_transactions.items()):
            if now >= tx.expires:
                del self.server_transactions[key]
                if tx.on_ack_timeout:
                    tx.on_ack_timeout()
                continue
            if tx.retry_at is not None and now >= tx.retry_at:
                self._send_raw(tx.sock, tx.payload, tx.addr)
                tx.interval = min(SIP_T2, tx.interval * 2)
                tx.retry_at = now + tx.interval
                LOG.info("retransmitting SIP response call_id=%s cseq=%s", tx.response.get("Call-ID"), tx.response.get("CSeq"))

    def handle_transaction_packet(self, sock, message: SIPMessage, addr) -> bool:
        key = transaction_key(sock, message)
        now = time.monotonic()
        if not message.is_response:
            if message.method == "ACK":
                self.log_sip("Peer -> proxy ACK", message)
                for tx in self.server_transactions.values():
                    response = tx.response
                    if (tx.sock is sock and parse_cseq(response.get("CSeq")) == (parse_cseq(message.get("CSeq"))[0], "INVITE")
                            and response.status_code >= 200 and response.get("Call-ID") == message.get("Call-ID")
                            # RFC 3261 12.2.2: dialog identity uses tags, not formatted address headers.
                            and extract_tag(response.get("From")) == extract_tag(message.get("From"))
                            and extract_tag(response.get("To")) == extract_tag(message.get("To"))
                            and (response.status_code < 300 or transaction_key(sock, message, "INVITE") == transaction_key(sock, response))):
                        tx.retry_at = None
                        tx.on_ack_timeout = None
                        if response.status_code >= 300:
                            tx.expires = now + SIP_T4
                        LOG.info("INVITE ACK matched call_id=%s cseq=%s local_port=%s", message.get("Call-ID"), message.get("CSeq"), sock.getsockname()[1])
                        break
                else:
                    LOG.warning("INVITE ACK unmatched call_id=%s cseq=%s local_port=%s", message.get("Call-ID"), message.get("CSeq"), sock.getsockname()[1])
                return True  # ACK never receives a response, including after expiry.
            cached = self.server_transactions.get(key)
            if cached is not None:
                self._send_raw(cached.sock, cached.payload, cached.addr)
                return True
            if message.method == "CANCEL":
                invite = self.server_transactions.get(transaction_key(sock, message, "INVITE"))
                if invite is None or invite.response.status_code >= 200:
                    code, reason = (481, "Call/Transaction Does Not Exist") if invite is None else (200, "OK")
                    self.send_sip(sock, build_response(message, code, reason, message.get("To") or ""), None if sock is self.downstream_sock else addr)
                    return True
            return False
        tx = self.client_transactions.get(key)
        if tx is None:
            return parse_cseq(message.get("CSeq"))[1] in {"INVITE", "BYE", "CANCEL"}
        code = message.status_code
        if tx.response is not None:
            if tx.ack is not None and code == tx.response.status_code and message.get("To") == tx.response.get("To"):
                self._send_raw(tx.sock, tx.ack, tx.addr)
            return True
        if code < 200:
            if not tx.provisional and tx.request.method == "INVITE" and not tx.timed_out:
                tx.expires = now + self.config.invite_timeout
            tx.provisional = True
            tx.retry_at = None if tx.request.method == "INVITE" else now + SIP_T2
            if tx.pending_cancel is not None:
                payload, tx.pending_cancel = tx.pending_cancel, None
                self.send_sip(tx.sock, payload, tx.addr)
            if tx.on_response and not tx.timed_out:
                tx.on_response(message)
            return True
        tx.response = message
        tx.retry_at = None
        tx.pending_cancel = None
        tx.expires = now + (SIP_TRANSACTION_TIMEOUT if tx.request.method == "INVITE" else SIP_T4)
        LOG.info("SIP transaction completed call_id=%s cseq=%s status=%s", message.get("Call-ID"), message.get("CSeq"), code)
        if tx.on_response is None:
            self.log_sip("Peer -> proxy transaction response", message)
        if tx.request.method == "INVITE" and code >= 300:
            headers = filter_headers(tx.request, {"Via", "From", "Call-ID", "Max-Forwards", "Route"})
            headers.extend([("To", message.get("To") or ""), ("CSeq", f"{parse_cseq(tx.request.get('CSeq'))[0]} ACK"), ("Content-Length", "0")])
            tx.ack = SIPMessage(f"ACK {tx.request.request_uri} SIP/2.0", headers, b"").to_bytes()
            self.log_sip("Proxy -> peer non-2xx ACK", parse_sip_message(tx.ack))
            self._send_raw(tx.sock, tx.ack, tx.addr)
        if tx.on_response:
            tx.on_response(message)
        return True

    def receive_call_response(self, session, response: SIPMessage) -> None:
        handler = self.handle_downstream_response if isinstance(session, CallSession) else self.handle_upstream_response
        if handler(session, response):
            code = response.status_code
            state = "timeout" if code == 408 else "rejected" if 300 <= code < 500 else "failed"
            self.finish_call(session, state, "invite_timeout" if code == 408 else "peer_response", code)

    def end_unacknowledged_call(self, session) -> None:
        if session.finished:
            return
        LOG.warning("terminating call after missing INVITE ACK upstream_call_id=%s downstream_call_id=%s", session.upstream_call_id, session.downstream_call_id)
        if isinstance(session, CallSession):
            self.send_downstream_bye(session)
            self.send_upstream_bye(session)
        else:
            self.send_upstream_bye_inbound(session)
            self.send_downstream_bye_inbound(session)
        self.finish_call(session, "failed", "ack_timeout")

    def log_sip(self, label: str, message: SIPMessage) -> None:
        if not self.config.trace_sip:
            return
        LOG.info("%s\n%s", label, format_sip_message(message))
        headers = identity_headers(message)
        if headers:
            LOG.info("%s identity_headers=%s", label, headers)

    def _discover_advertised_host(self) -> str:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((self.config.proxy_host, self.config.proxy_port))
            host, _ = probe.getsockname()
            return host
        finally:
            probe.close()

    def run(self) -> None:
        LOG.info(
            "orange proxy upstream=%s:%s downstream=%s:%s Orange=%s:%s advertised_host=%s",
            self.config.bind_host,
            self.config.bind_port,
            self.config.bind_host,
            self.config.downstream_port,
            self.config.proxy_host,
            self.config.proxy_port,
            self.advertised_host,
        )
        while True:
            try:
                self.ensure_registered()
            except Exception:
                LOG.exception("background register refresh failed")
            self.tick_transactions()
            ready, _, _ = select.select([self.sock, self.downstream_sock], [], [], 0.25)
            for active_sock in ready:
                data, addr = active_sock.recvfrom(MAX_PACKET)
                try:
                    message = parse_sip_message(data)
                    self.handle_packet(active_sock, message, addr)
                except (ValueError, IndexError):
                    LOG.exception("invalid SIP packet from %s:%s", addr[0], addr[1])

    def handle_packet(self, sock, message: SIPMessage, addr: tuple[str, int]) -> None:
        if sock is self.downstream_sock and self.handle_registration_response(message):
            return
        if self.handle_transaction_packet(sock, message, addr):
            return
        if message.is_response:
            LOG.debug("dropping unsolicited response %s", message.start_line)
            return

        method = message.method.upper()
        session = self.find_session(sock, message)
        if session is not None:
            if isinstance(session, CallSession):
                handler = self.handle_upstream_request if sock is self.sock else self.handle_downstream_request
                handler(session, message, addr)
            elif sock is self.sock:
                self.handle_upstream_request_inbound(session, message, addr)
            else:
                self.handle_downstream_request_inbound(session, message)
            return

        if method == "OPTIONS":
            code, reason = 200, "OK"
        elif extract_tag(message.get("To")) or method in {"BYE", "CANCEL"}:
            code, reason = 481, "Call/Transaction Does Not Exist"
        elif method == "INVITE":
            if sock is self.sock:
                self.handle_invite(message, addr)
            else:
                self.log_sip("Orange -> proxy inbound INVITE", message)
                self.handle_inbound_invite(message, addr)
            return
        else:
            code, reason = 405, "Method Not Allowed"
        response = build_response(message, code, reason, message.get("To") or "",
                                  extra_headers=[("Allow", ALLOWED_METHODS), ("User-Agent", self.config.user_agent)])
        self.send_sip(sock, response, None if sock is self.downstream_sock else addr)

    def find_session(self, sock, request: SIPMessage):
        # CANCEL matches the initial transaction; in-dialog requests match both tags.
        for key, session in self.sessions.items():
            if request.method == "CANCEL":
                if key == transaction_key(sock, request, "INVITE"):
                    return session
                continue
            if sock is self.sock:
                call_id = session.upstream_call_id
                if isinstance(session, CallSession):
                    local_tag, remote_tag = session.upstream_tag, extract_tag(session.upstream_from)
                else:
                    local_tag, remote_tag = extract_tag(session.upstream_from), session.upstream_to_tag
            else:
                call_id = session.downstream_call_id
                if isinstance(session, CallSession):
                    local_tag, remote_tag = session.downstream_from_tag, session.downstream_to_tag
                else:
                    local_tag, remote_tag = session.downstream_to_tag, extract_tag(session.downstream_request.get("From"))
            if (request.get("Call-ID") == call_id and local_tag is not None
                    and extract_tag(request.get("To")) == local_tag
                    and extract_tag(request.get("From")) == remote_tag):
                return session
        return None

    def add_session(self, session) -> bool:
        sock = self.sock if isinstance(session, CallSession) else self.downstream_sock
        request = session.upstream_request if isinstance(session, CallSession) else session.downstream_request
        if self.config.max_calls and len(self.sessions) >= self.config.max_calls:
            response = build_response(request, 486, "Busy Here", with_tag(request.get("To") or "", new_tag()))
            self.send_sip(sock, response, session.upstream_addr if sock is self.sock else None)
            self.finish_call(session, "rejected", "capacity_limit", 486)
            return False
        self.sessions[transaction_key(sock, request)] = session
        self.log_call_state(session, "received")
        return True

    def log_call_state(self, session, state: str, reason: str = "", sip_status: int = 0) -> None:
        LOG.info("call state=%s direction=%s upstream_call_id=%s downstream_call_id=%s "
                 "active_calls=%s max_calls=%s reason=%s sip_status=%s",
                 state, "outbound" if isinstance(session, CallSession) else "inbound",
                 session.upstream_call_id, session.downstream_call_id, len(self.sessions),
                 self.config.max_calls, reason or "-", sip_status)

    def finish_call(self, session, state: str, reason: str, sip_status: int = 0) -> None:
        if session.finished:
            return
        session.finished = True
        sock = self.sock if isinstance(session, CallSession) else self.downstream_sock
        request = session.upstream_request if isinstance(session, CallSession) else session.downstream_request
        self.sessions.pop(transaction_key(sock, request), None)
        # Transaction callbacks and ACK/BYE caches keep their own lifetimes.
        self.log_call_state(session, state, reason, sip_status)

    def handle_invite(self, upstream_request: SIPMessage, upstream_addr: tuple[str, int]) -> None:
        trying = build_response(upstream_request, 100, "Trying", upstream_request.get("To") or "")
        self.send_upstream(trying, upstream_addr)
        try:
            self.ensure_registered()
        except Exception as exc:
            LOG.exception("registration failed")
            failure = build_response(
                upstream_request,
                503,
                "Orange registration failed",
                with_tag(upstream_request.get("To") or "", new_tag()),
                body=str(exc).encode(),
                extra_headers=[("Content-Type", "text/plain"), ("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(failure, upstream_addr)
            return

        called_number = self.extract_called_number(upstream_request)
        if not called_number:
            failure = build_response(
                upstream_request,
                400,
                "Missing destination number",
                with_tag(upstream_request.get("To") or "", new_tag()),
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(failure, upstream_addr)
            return

        upstream_contact = upstream_request.get("Contact")
        if upstream_contact:
            upstream_remote_target = extract_uri(upstream_contact)
        else:
            upstream_remote_target = f"sip:livekit@{upstream_addr[0]}:{upstream_addr[1]}"

        session = CallSession(
            upstream_request=upstream_request,
            upstream_addr=upstream_addr,
            upstream_tag=new_tag(),
            upstream_remote_target=upstream_remote_target,
            upstream_next_cseq=parse_cseq(upstream_request.get("CSeq"))[0] + 1,
            called_number=called_number,
            downstream_call_id=new_call_id("orange-bridge"),
            downstream_from_tag=new_tag(),
            downstream_route_headers=[self.register_state.service_route] if self.register_state.service_route else [],
        )

        if self.add_session(session):
            self.send_downstream_invite(session)

    def handle_inbound_invite(self, downstream_request: SIPMessage, downstream_addr: tuple[str, int]) -> None:
        trying = build_response(downstream_request, 100, "Trying", downstream_request.get("To") or "")
        self.send_downstream(trying)

        called_number = self.extract_called_number(downstream_request)
        if not called_number:
            failure = build_response(
                downstream_request,
                400,
                "Missing destination number",
                with_tag(downstream_request.get("To") or "", new_tag()),
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_downstream(failure)
            return

        upstream_from = downstream_request.get("From") or f"<sip:{self.config.from_number}@{self.config.domain}>;tag={new_tag()}"
        downstream_to = downstream_request.get("To") or f"<sip:{called_number}@{self.config.domain}>"
        upstream_request_uri = f"sip:{called_number}@{self.config.upstream_host}:{self.config.upstream_port}"
        upstream_request = self.build_upstream_invite(
            downstream_request,
            called_number=called_number,
            upstream_request_uri=upstream_request_uri,
            upstream_from=upstream_from,
            downstream_to=downstream_to,
        )
        self.log_sip("Proxy -> SIP server inbound INVITE", upstream_request)
        upstream_call_id = upstream_request.get("Call-ID") or new_call_id("lk-inbound")
        invite_cseq, _ = parse_cseq(upstream_request.get("CSeq"))
        upstream_branch_match = re.search(r"branch=([^;]+)", upstream_request.get("Via") or "")
        upstream_branch = upstream_branch_match.group(1) if upstream_branch_match else new_branch()
        session = InboundCallSession(
            downstream_request=downstream_request,
            downstream_addr=downstream_addr,
            downstream_to_tag=new_tag(),
            called_number=called_number,
            upstream_call_id=upstream_call_id,
            upstream_request_uri=upstream_request_uri,
            upstream_from=upstream_from,
            upstream_to=downstream_to,
            upstream_invite_cseq=invite_cseq,
            upstream_next_cseq=invite_cseq + 1,
            upstream_invite_branch=upstream_branch,
            upstream_remote_target=upstream_request_uri,
        )

        if not self.add_session(session):
            return

        LOG.info("accepting Orange inbound number=%s call_id=%s", called_number, session.downstream_call_id)
        LOG.info(
            "inbound registration clock call_id=%s expires_at=%.3f remaining=%.3fs refresh_margin=%ss",
            session.downstream_call_id,
            self.register_state.valid_until,
            self.register_state.valid_until - time.time(),
            self.config.register_margin,
        )
        self.send_upstream(upstream_request.to_bytes(), (self.config.upstream_host, self.config.upstream_port),
                           on_response=lambda response: self.receive_call_response(session, response))

    def ensure_registered(self) -> None:
        """Advance REGISTER without reading the socket or blocking the call loop."""
        now = time.monotonic()
        transaction = self.register_transaction
        if transaction is not None:
            if now >= transaction.deadline:
                self._registration_failed("REGISTER response timeout")
            elif now >= transaction.next_send:
                self.send_downstream(transaction.payload)
                transaction.retry_interval = min(4.0, transaction.retry_interval * 2)
                transaction.next_send = now + transaction.retry_interval
                LOG.info("retransmitting REGISTER call_id=%s cseq=%s", transaction.call_id, transaction.cseq)
            return
        if now < self.register_retry_at or self.register_state.valid_until - self.config.register_margin > time.time():
            return
        self.register_transaction = RegisterTransaction(new_call_id("reg"), new_tag(8))
        self._send_register(None)

    def _send_register(self, auth_header: Optional[tuple[str, str]]) -> None:
        transaction = self.register_transaction
        assert transaction is not None
        transaction.cseq += 1
        transaction.payload = self.build_register(
            call_id=transaction.call_id,
            from_tag=transaction.from_tag,
            branch=new_branch(),
            cseq=transaction.cseq,
            auth_header=auth_header,
        )
        transaction.deadline = time.monotonic() + self.config.invite_timeout
        transaction.retry_interval = 0.5
        transaction.next_send = time.monotonic() + transaction.retry_interval
        self.log_sip("Proxy -> Orange transaction", parse_sip_message(transaction.payload))
        self.send_downstream(transaction.payload)

    def _registration_failed(self, reason: str) -> None:
        LOG.error("Orange registration failed: %s", reason)
        self.register_transaction = None
        self.register_retry_at = time.monotonic() + 5.0

    def handle_registration_response(self, message: SIPMessage) -> bool:
        transaction = self.register_transaction
        if not message.is_response or parse_cseq(message.get("CSeq"))[1] != "REGISTER":
            return False
        self.log_sip("Orange -> proxy transaction packet", message)
        if transaction is None or message.get("Call-ID") != transaction.call_id:
            return True  # delayed response to an earlier registration
        if parse_cseq(message.get("CSeq"))[0] != transaction.cseq:
            return True
        code = message.status_code
        if code < 200:
            transaction.retry_interval = 4.0
            transaction.next_send = time.monotonic() + 4.0
        elif code in (401, 407) and transaction.cseq < 4:
            header_name, params = digest_challenge(message)
            if not header_name or not params:
                self._registration_failed("auth challenge has no usable parameters")
                return True
            auth = build_digest_auth(
                header_name, params, "REGISTER", f"sip:{self.config.domain}",
                self.config.auth_username, self.config.password,
            )
            self._send_register(auth)
        elif code == 200:
            self.register_state.service_route = parse_service_route(message)
            expires = parse_expires(message, self.config.register_expires)
            self.register_state.valid_until = time.time() + expires
            self.register_transaction = None
            self.register_retry_at = 0.0
            LOG.info("registered with Orange, expires in %ss, service_route=%s", expires, self.register_state.service_route)
        else:
            self._registration_failed(f"{code} {message.reason}")
        return True

    def build_register(
        self,
        call_id: str,
        from_tag: str,
        branch: str,
        cseq: int,
        auth_header: Optional[tuple[str, str]],
    ) -> bytes:
        uri = f"sip:{self.config.domain}"
        headers = [
            ("Via", f"SIP/2.0/UDP {self.advertised_host}:{self.config.downstream_port};branch={branch};rport"),
            ("Max-Forwards", "70"),
            ("To", f"<sip:{self.config.from_number}@{self.config.domain}>"),
            ("From", f"<sip:{self.config.from_number}@{self.config.domain}>;tag={from_tag}"),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} REGISTER"),
            (
                "Contact",
                f"<sip:{self.config.from_number}@{self.advertised_host}:{self.config.register_contact_port};transport=udp>;expires={self.config.register_expires}",
            ),
            ("Expires", str(self.config.register_expires)),
            ("User-Agent", self.config.user_agent),
            ("Allow", ALLOWED_METHODS),
        ]
        if auth_header:
            headers.append(auth_header)
        headers.append(("Content-Length", "0"))
        return SIPMessage(
            start_line=f"REGISTER {uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()

    def extract_called_number(self, message: SIPMessage) -> str:
        request_uri = extract_uri(message.request_uri)
        user, _, _ = parse_uri(request_uri)
        if user:
            return user
        to_value = message.get("To")
        if to_value:
            user, _, _ = parse_uri(to_value)
            return user
        return ""

    def send_downstream_invite(self, session: CallSession, auth_header: Optional[tuple[str, str]] = None) -> None:
        session.downstream_last_branch = new_branch()
        invite_uri = f"sip:{session.called_number}@{self.config.domain}"
        body = session.upstream_request.body
        headers = [
            ("Via", f"SIP/2.0/UDP {self.advertised_host}:{self.config.downstream_port};branch={session.downstream_last_branch};rport"),
            ("Max-Forwards", "70"),
            ("To", f"<{invite_uri}>"),
            (
                "From",
                f"<sip:{self.config.from_number}@{self.config.domain}>;tag={session.downstream_from_tag}",
            ),
            ("Call-ID", session.downstream_call_id),
            ("CSeq", f"{session.downstream_invite_cseq} INVITE"),
            (
                "Contact",
                f"<sip:{self.config.from_number}@{self.advertised_host}:{self.config.downstream_port};transport=udp>",
            ),
            ("User-Agent", self.config.user_agent),
            ("Allow", ALLOWED_METHODS),
            ("P-Preferred-Identity", f"<sip:{self.config.from_number}@{self.config.domain}>"),
        ]
        for route in session.downstream_route_headers:
            headers.append(("Route", route))
        if auth_header:
            headers.append(auth_header)
        content_type = session.upstream_request.get("Content-Type") or "application/sdp"
        headers.append(("Content-Type", content_type))
        headers.append(("Content-Length", str(len(body))))
        payload = SIPMessage(
            start_line=f"INVITE {invite_uri} SIP/2.0",
            headers=headers,
            body=body,
        ).to_bytes()
        LOG.info("dialing Orange number=%s call_id=%s", session.called_number, session.downstream_call_id)
        self.log_sip("Proxy -> Orange outbound INVITE", parse_sip_message(payload))
        self.send_downstream(payload, on_response=lambda response: self.receive_call_response(session, response))

    def handle_downstream_response(self, session: CallSession, response: SIPMessage) -> bool:
        self.log_sip("Orange -> proxy outbound response", response)
        code = response.status_code
        cseq_number, cseq_method = parse_cseq(response.get("CSeq"))
        LOG.info("Orange response %s %s for %s", code, response.reason, cseq_method or "?")

        if cseq_method == "INVITE":
            if code < 200 and session.cancelled:
                return False
            if code in (401, 407):
                if session.cancelled:
                    return True
                if session.auth_attempts >= 3:
                    self.forward_downstream_failure(session, code, response.reason, response.body, response)
                    return True
                header_name, params = digest_challenge(response)
                if not header_name or not params or not params.get("realm") or not params.get("nonce"):
                    self.forward_downstream_failure(session, 502, "Orange auth challenge parse failed", b"")
                    self.finish_call(session, "failed", "invalid_auth_challenge", 502)
                    return True
                auth = build_digest_auth(
                    header_name,
                    params,
                    "INVITE",
                    f"sip:{session.called_number}@{self.config.domain}",
                    self.config.auth_username,
                    self.config.password,
                )
                session.downstream_invite_cseq = cseq_number + 1
                session.auth_attempts += 1
                self.send_downstream_invite(session, auth_header=auth)
                return False

            if code < 200:
                if code != 100:
                    self.forward_provisional(session, response)
                return False

            if code == 200:
                session.answered = True
                session.downstream_to_tag = extract_tag(response.get("To"))
                contact = response.get("Contact")
                if contact:
                    session.downstream_contact_uri = extract_uri(contact)
                session.downstream_route_headers = list(reversed(response.get_all("Record-Route")))
                self.send_downstream_ack(session)
                if session.cancelled:
                    self.send_downstream_bye(session)
                    return True
                self.forward_answer(session, response)
                self.log_call_state(session, "answered", sip_status=code)
                return False

            if not session.cancelled:
                self.forward_downstream_failure(session, code, response.reason, response.body, response)
            session.cancelled = True
            if code == 408:
                self.send_downstream_cancel(session)
            return True

        if cseq_method == "CANCEL":
            return False

        if cseq_method == "BYE":
            return True

        return False

    def forward_provisional(self, session: CallSession, response: SIPMessage) -> None:
        body = response.body
        extra_headers = filter_headers(
            response,
            {"Content-Type", "Require", "Supported", "Session-Expires", "Min-SE", "Reason"},
        )
        extra_headers.append(("User-Agent", self.config.user_agent))
        payload = build_response(
            session.upstream_request,
            response.status_code,
            response.reason,
            with_tag(session.upstream_to, session.upstream_tag),
            body=body,
            extra_headers=extra_headers,
        )
        self.send_upstream(payload, session.upstream_addr)

    def forward_answer(self, session: CallSession, response: SIPMessage) -> None:
        body = response.body
        extra_headers = filter_headers(
            response,
            {"Content-Type", "Require", "Supported", "Session-Expires", "Min-SE", "Reason"},
        )
        extra_headers.extend(
            [
                (
                    "Contact",
                    f"<sip:orange-proxy@{self.config.upstream_host}:{self.config.bind_port};transport=udp>",
                ),
                ("Allow", ALLOWED_METHODS),
                ("User-Agent", self.config.user_agent),
            ]
        )
        payload = build_response(
            session.upstream_request,
            200,
            "OK",
            with_tag(session.upstream_to, session.upstream_tag),
            body=body,
            extra_headers=extra_headers,
        )
        self.send_upstream(payload, session.upstream_addr, on_ack_timeout=lambda: self.end_unacknowledged_call(session))

    def forward_downstream_failure(self, session: CallSession, code: int, reason: str, body: bytes, response: Optional[SIPMessage] = None) -> None:
        extra_headers: list[tuple[str, str]] = [("User-Agent", self.config.user_agent)]
        if response is not None:
            extra_headers.extend(filter_headers(response, {"Content-Type", "Reason", "Warning", "Retry-After"}))
        if body and not (response and response.get("Content-Type")):
            extra_headers.append(("Content-Type", "text/plain"))
        payload = build_response(
            session.upstream_request,
            code,
            reason or "Call Failed",
            with_tag(session.upstream_to, session.upstream_tag),
            body=body,
            extra_headers=extra_headers,
        )
        self.send_upstream(payload, session.upstream_addr)

    def handle_upstream_request(
        self,
        session: CallSession,
        request: SIPMessage,
        addr: tuple[str, int],
    ) -> bool:
        method = request.method.upper()
        LOG.info("SIP server request %s for %s", method, session.upstream_call_id)

        if method == "ACK":
            return False

        if method == "CANCEL" and not session.answered:
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(ok, addr)
            session.cancelled = True
            self.send_downstream_cancel(session)
            cancelled = build_response(
                session.upstream_request,
                487,
                "Request Terminated",
                with_tag(session.upstream_to, session.upstream_tag),
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(cancelled, session.upstream_addr)
            self.finish_call(session, "cancelled", "application_cancel", 487)
            return True

        if method == "BYE" and session.answered:
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(ok, addr)
            self.send_downstream_bye(session)
            self.finish_call(session, "completed", "application_bye")
            return True

        if method == "OPTIONS":
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("Allow", ALLOWED_METHODS), ("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(ok, addr)
            return False

        failure = build_response(
            request,
            405,
            "Method Not Allowed",
            request.get("To") or "",
            extra_headers=[("Allow", ALLOWED_METHODS), ("User-Agent", self.config.user_agent)],
        )
        self.send_upstream(failure, addr)
        return False

    def handle_downstream_request(
        self,
        session: CallSession,
        request: SIPMessage,
        addr: tuple[str, int],
    ) -> bool:
        method = request.method.upper()
        LOG.info("Orange request %s for %s", method, session.downstream_call_id)

        if method == "BYE":
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_downstream(ok)
            if session.answered:
                self.send_upstream_bye(session)
            self.finish_call(session, "completed", "orange_bye")
            return True

        if method == "OPTIONS":
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("Allow", ALLOWED_METHODS), ("User-Agent", self.config.user_agent)],
            )
            self.send_downstream(ok)
            return False

        not_impl = build_response(
            request,
            501,
            "Not Implemented",
            request.get("To") or "",
            extra_headers=[("User-Agent", self.config.user_agent)],
        )
        self.send_downstream(not_impl)
        return False

    def send_downstream_cancel(self, session: CallSession) -> None:
        invite_uri = f"sip:{session.called_number}@{self.config.domain}"
        to_value = f"<{invite_uri}>"
        if session.downstream_to_tag:
            to_value = with_tag(to_value, session.downstream_to_tag)
        headers = [
            ("Via", f"SIP/2.0/UDP {self.advertised_host}:{self.config.downstream_port};branch={session.downstream_last_branch};rport"),
            ("Max-Forwards", "70"),
            ("To", to_value),
            (
                "From",
                f"<sip:{self.config.from_number}@{self.config.domain}>;tag={session.downstream_from_tag}",
            ),
            ("Call-ID", session.downstream_call_id),
            ("CSeq", f"{session.downstream_invite_cseq} CANCEL"),
            ("User-Agent", self.config.user_agent),
        ]
        for route in session.downstream_route_headers:
            headers.append(("Route", route))
        headers.append(("Content-Length", "0"))
        payload = SIPMessage(
            start_line=f"CANCEL {invite_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        self.send_downstream(payload)

    def send_downstream_ack(self, session: CallSession) -> None:
        if not session.downstream_to_tag:
            return
        request_uri = session.downstream_contact_uri or f"sip:{session.called_number}@{self.config.domain}"
        headers = [
            ("Via", f"SIP/2.0/UDP {self.advertised_host}:{self.config.downstream_port};branch={new_branch()};rport"),
            ("Max-Forwards", "70"),
            ("To", with_tag(f"<sip:{session.called_number}@{self.config.domain}>", session.downstream_to_tag)),
            (
                "From",
                f"<sip:{self.config.from_number}@{self.config.domain}>;tag={session.downstream_from_tag}",
            ),
            ("Call-ID", session.downstream_call_id),
            ("CSeq", f"{session.downstream_invite_cseq} ACK"),
            ("User-Agent", self.config.user_agent),
            ("Content-Length", "0"),
        ]
        for route in session.downstream_route_headers:
            headers.append(("Route", route))
        payload = SIPMessage(
            start_line=f"ACK {request_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        self.send_downstream(payload)

    def send_downstream_bye(self, session: CallSession) -> None:
        request_uri = session.downstream_contact_uri or f"sip:{session.called_number}@{self.config.domain}"
        headers = [
            ("Via", f"SIP/2.0/UDP {self.advertised_host}:{self.config.downstream_port};branch={new_branch()};rport"),
            ("Max-Forwards", "70"),
            ("To", with_tag(f"<sip:{session.called_number}@{self.config.domain}>", session.downstream_to_tag or "")),
            (
                "From",
                f"<sip:{self.config.from_number}@{self.config.domain}>;tag={session.downstream_from_tag}",
            ),
            ("Call-ID", session.downstream_call_id),
            ("CSeq", f"{session.downstream_invite_cseq + 1} BYE"),
            ("User-Agent", self.config.user_agent),
            ("Content-Length", "0"),
        ]
        for route in session.downstream_route_headers:
            headers.append(("Route", route))
        payload = SIPMessage(
            start_line=f"BYE {request_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        self.send_downstream(payload)

    def send_upstream_bye(self, session: CallSession) -> None:
        request_uri = session.upstream_remote_target
        original_from = session.upstream_from
        original_to = session.upstream_to
        headers = [
            ("Via", f"SIP/2.0/UDP {self.config.upstream_host}:{self.config.bind_port};branch={new_branch()};rport"),
            ("Max-Forwards", "70"),
            ("To", original_from),
            ("From", with_tag(original_to, session.upstream_tag)),
            ("Call-ID", session.upstream_call_id),
            ("CSeq", f"{session.upstream_next_cseq} BYE"),
            ("User-Agent", self.config.user_agent),
            ("Content-Length", "0"),
        ]
        payload = SIPMessage(
            start_line=f"BYE {request_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        _, host, port = parse_uri(request_uri)
        self.send_upstream(payload, (host, port))

    def build_upstream_invite(
        self,
        downstream_request: SIPMessage,
        *,
        called_number: str,
        upstream_request_uri: str,
        upstream_from: str,
        downstream_to: str,
    ) -> SIPMessage:
        branch = new_branch()
        call_id = new_call_id("lk-inbound")
        content_type = downstream_request.get("Content-Type") or "application/sdp"
        body = downstream_request.body
        headers = [
            ("Via", f"SIP/2.0/UDP {self.config.upstream_host}:{self.config.bind_port};branch={branch};rport"),
            ("Max-Forwards", "70"),
            ("To", downstream_to),
            ("From", upstream_from),
            ("Call-ID", call_id),
            ("CSeq", "1 INVITE"),
            ("Contact", f"<sip:orange-proxy@{self.config.upstream_host}:{self.config.bind_port};transport=udp>"),
            ("User-Agent", self.config.user_agent),
            ("Allow", ALLOWED_METHODS),
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
        ]
        # Preserve forwarding identity. Combine repeated fields because downstream
        # header-to-attribute mappings may expose only the first header value.
        for name in ("Diversion", "History-Info"):
            values = downstream_request.get_all(name)
            if values:
                headers.append((name, ", ".join(values)))
        return SIPMessage(
            start_line=f"INVITE {upstream_request_uri} SIP/2.0",
            headers=headers,
            body=body,
        )

    def handle_upstream_response(self, session: InboundCallSession, response: SIPMessage) -> bool:
        code = response.status_code
        cseq_number, cseq_method = parse_cseq(response.get("CSeq"))
        LOG.info("SIP server response %s %s for %s", code, response.reason, cseq_method or "?")
        self.log_sip("SIP server -> proxy inbound response", response)

        if cseq_method == "INVITE":
            if code < 200:
                if code != 100 and not session.downstream_cancelled:
                    self.forward_upstream_provisional(session, response)
                return False

            if code == 200:
                session.answered = True
                session.upstream_to_tag = extract_tag(response.get("To"))
                contact = response.get("Contact")
                if contact:
                    session.upstream_remote_target = extract_uri(contact)
                session.upstream_route_headers = list(reversed(response.get_all("Record-Route")))
                self.send_upstream_ack_inbound(session)
                if session.downstream_cancelled:
                    self.send_upstream_bye_inbound(session)
                    return True
                self.forward_upstream_answer(session, response)
                self.log_call_state(session, "answered", sip_status=code)
                return False

            if not session.downstream_cancelled:
                self.forward_upstream_failure(session, code, response.reason, response.body, response)
            session.downstream_cancelled = True
            if code == 408:
                self.send_upstream_cancel_inbound(session)
            return True

        if cseq_method == "CANCEL":
            return False

        if cseq_method == "BYE":
            return True

        return False

    def forward_upstream_provisional(self, session: InboundCallSession, response: SIPMessage) -> None:
        body = response.body
        extra_headers = filter_headers(
            response,
            {"Content-Type", "Require", "Supported", "Session-Expires", "Min-SE", "Reason"},
        )
        extra_headers.append(("User-Agent", self.config.user_agent))
        payload = build_response(
            session.downstream_request,
            response.status_code,
            response.reason,
            with_tag(session.downstream_request.get("To") or session.upstream_to, session.downstream_to_tag),
            body=body,
            extra_headers=extra_headers,
        )
        self.log_sip("Proxy -> Orange inbound provisional", parse_sip_message(payload))
        self.send_downstream(payload)

    def forward_upstream_answer(self, session: InboundCallSession, response: SIPMessage) -> None:
        body = response.body
        extra_headers = filter_headers(
            response,
            {"Content-Type", "Require", "Supported", "Session-Expires", "Min-SE", "Reason"},
        )
        extra_headers.extend(
            [
                (
                    "Contact",
                    f"<sip:orange-proxy@{self.advertised_host}:{self.config.downstream_port};transport=udp>",
                ),
                ("Allow", ALLOWED_METHODS),
                ("User-Agent", self.config.user_agent),
            ]
        )
        payload = build_response(
            session.downstream_request,
            200,
            "OK",
            with_tag(session.downstream_request.get("To") or session.upstream_to, session.downstream_to_tag),
            body=body,
            extra_headers=extra_headers,
        )
        self.log_sip("Proxy -> Orange inbound 200 OK", parse_sip_message(payload))
        self.send_downstream(payload, on_ack_timeout=lambda: self.end_unacknowledged_call(session))

    def forward_upstream_failure(self, session: InboundCallSession, code: int, reason: str, body: bytes, response: Optional[SIPMessage] = None) -> None:
        extra_headers: list[tuple[str, str]] = [("User-Agent", self.config.user_agent)]
        if response is not None:
            extra_headers.extend(filter_headers(response, {"Content-Type", "Reason", "Warning", "Retry-After"}))
        if body and not (response and response.get("Content-Type")):
            extra_headers.append(("Content-Type", "text/plain"))
        payload = build_response(
            session.downstream_request,
            code,
            reason or "Call Failed",
            with_tag(session.downstream_request.get("To") or session.upstream_to, session.downstream_to_tag),
            body=body,
            extra_headers=extra_headers,
        )
        self.log_sip("Proxy -> Orange inbound failure", parse_sip_message(payload))
        self.send_downstream(payload)

    def handle_upstream_request_inbound(
        self,
        session: InboundCallSession,
        request: SIPMessage,
        addr: tuple[str, int],
    ) -> bool:
        method = request.method.upper()
        LOG.info("SIP server request %s for inbound %s", method, session.upstream_call_id)
        self.log_sip("SIP server -> proxy inbound request", request)

        if method == "ACK":
            return False

        if method == "BYE" and session.answered:
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(ok, addr)
            self.send_downstream_bye_inbound(session)
            self.finish_call(session, "completed", "application_bye")
            return True

        if method == "OPTIONS":
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("Allow", ALLOWED_METHODS), ("User-Agent", self.config.user_agent)],
            )
            self.send_upstream(ok, addr)
            return False

        failure = build_response(
            request,
            405,
            "Method Not Allowed",
            request.get("To") or "",
            extra_headers=[("Allow", ALLOWED_METHODS), ("User-Agent", self.config.user_agent)],
        )
        self.send_upstream(failure, addr)
        return False

    def handle_downstream_request_inbound(self, session: InboundCallSession, request: SIPMessage) -> bool:
        method = request.method.upper()
        LOG.info("Orange request %s for inbound %s", method, session.downstream_call_id)
        self.log_sip("Orange -> proxy inbound in-dialog request", request)

        if method == "ACK":
            return False

        if method == "CANCEL" and not session.answered:
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_downstream(ok)
            session.downstream_cancelled = True
            self.send_upstream_cancel_inbound(session)
            self.forward_upstream_failure(session, 487, "Request Terminated", b"")
            self.finish_call(session, "cancelled", "orange_cancel", 487)
            return True

        if method == "BYE" and session.answered:
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("User-Agent", self.config.user_agent)],
            )
            self.send_downstream(ok)
            self.send_upstream_bye_inbound(session)
            self.finish_call(session, "completed", "orange_bye")
            return True

        if method == "OPTIONS":
            ok = build_response(
                request,
                200,
                "OK",
                request.get("To") or "",
                extra_headers=[("Allow", ALLOWED_METHODS), ("User-Agent", self.config.user_agent)],
            )
            self.send_downstream(ok)
            return False

        not_impl = build_response(
            request,
            501,
            "Not Implemented",
            request.get("To") or "",
            extra_headers=[("User-Agent", self.config.user_agent)],
        )
        self.send_downstream(not_impl)
        return False

    def send_upstream_ack_inbound(self, session: InboundCallSession) -> None:
        if not session.upstream_to_tag:
            return
        request_uri = session.upstream_remote_target or session.upstream_request_uri
        headers = [
            ("Via", f"SIP/2.0/UDP {self.config.upstream_host}:{self.config.bind_port};branch={new_branch()};rport"),
            ("Max-Forwards", "70"),
            ("To", with_tag(session.upstream_to, session.upstream_to_tag)),
            ("From", session.upstream_from),
            ("Call-ID", session.upstream_call_id),
            ("CSeq", f"{session.upstream_invite_cseq} ACK"),
            ("User-Agent", self.config.user_agent),
            ("Content-Length", "0"),
        ]
        for route in session.upstream_route_headers:
            headers.append(("Route", route))
        payload = SIPMessage(
            start_line=f"ACK {request_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        self.log_sip("Proxy -> SIP server inbound ACK", parse_sip_message(payload))
        self.send_upstream(payload, (self.config.upstream_host, self.config.upstream_port))

    def send_upstream_cancel_inbound(self, session: InboundCallSession) -> None:
        headers = [
            ("Via", f"SIP/2.0/UDP {self.config.upstream_host}:{self.config.bind_port};branch={session.upstream_invite_branch};rport"),
            ("Max-Forwards", "70"),
            ("To", session.upstream_to),
            ("From", session.upstream_from),
            ("Call-ID", session.upstream_call_id),
            ("CSeq", f"{session.upstream_invite_cseq} CANCEL"),
            ("User-Agent", self.config.user_agent),
            ("Content-Length", "0"),
        ]
        payload = SIPMessage(
            start_line=f"CANCEL {session.upstream_request_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        self.log_sip("Proxy -> SIP server inbound CANCEL", parse_sip_message(payload))
        self.send_upstream(payload, (self.config.upstream_host, self.config.upstream_port))

    def send_upstream_bye_inbound(self, session: InboundCallSession) -> None:
        if not session.upstream_to_tag:
            return
        request_uri = session.upstream_remote_target or session.upstream_request_uri
        headers = [
            ("Via", f"SIP/2.0/UDP {self.config.upstream_host}:{self.config.bind_port};branch={new_branch()};rport"),
            ("Max-Forwards", "70"),
            ("To", with_tag(session.upstream_to, session.upstream_to_tag)),
            ("From", session.upstream_from),
            ("Call-ID", session.upstream_call_id),
            ("CSeq", f"{session.upstream_next_cseq} BYE"),
            ("User-Agent", self.config.user_agent),
            ("Content-Length", "0"),
        ]
        for route in session.upstream_route_headers:
            headers.append(("Route", route))
        payload = SIPMessage(
            start_line=f"BYE {request_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        self.log_sip("Proxy -> SIP server inbound BYE", parse_sip_message(payload))
        self.send_upstream(payload, (self.config.upstream_host, self.config.upstream_port))
        session.upstream_next_cseq += 1

    def send_downstream_bye_inbound(self, session: InboundCallSession) -> None:
        request_uri = extract_uri(session.downstream_request.get("Contact") or session.downstream_request.request_uri)
        if not request_uri:
            request_uri = f"sip:{session.called_number}@{self.config.domain}"
        cseq_number = parse_cseq(session.downstream_request.get("CSeq"))[0] + 1
        headers = [
            ("Via", f"SIP/2.0/UDP {self.advertised_host}:{self.config.downstream_port};branch={new_branch()};rport"),
            ("Max-Forwards", "70"),
            ("To", session.downstream_request.get("From") or ""),
            ("From", with_tag(session.downstream_request.get("To") or session.upstream_to, session.downstream_to_tag)),
            ("Call-ID", session.downstream_call_id),
            ("CSeq", f"{cseq_number} BYE"),
            ("User-Agent", self.config.user_agent),
            ("Content-Length", "0"),
        ]
        payload = SIPMessage(
            start_line=f"BYE {request_uri} SIP/2.0",
            headers=headers,
            body=b"",
        ).to_bytes()
        self.log_sip("Proxy -> Orange inbound BYE", parse_sip_message(payload))
        self.send_downstream(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge Orange Spain SIP calls to a local SIP server.")
    parser.add_argument("--env-file", type=Path, help="Read the credential file written by extract_livebox_sip.py.")
    args = parser.parse_args()
    try:
        if args.env_file:
            for raw_line in args.env_file.read_text().splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())
        logging.basicConfig(
            level=os.environ.get("ORANGE_PROXY_LOG_LEVEL", "INFO").upper(),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        config = BridgeConfig.from_env()
    except Exception as exc:
        LOG.error("%s", exc)
        return 1
    bridge = OrangeSIPBridge(config)
    try:
        bridge.run()
    except KeyboardInterrupt:
        LOG.info("stopping")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
