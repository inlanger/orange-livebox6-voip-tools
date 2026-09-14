# Orange Spain SIP Bridge

A Python SIP signaling bridge between Orange Spain and a local SIP server. It keeps the Orange line registered, forwards incoming and outgoing calls, and handles authentication, retransmissions, cancellation, and hangup. It uses only the Python standard library.

## Run with Python

Requirements: Python 3.10+, Orange SIP credentials, a network path to the operator, and a SIP server that handles media.

From the repository root, use the [extractor](../README.md#extract-and-run) to create `.orange_voip.env`, then run:

```bash
python3 orange-proxy/proxy.py --env-file .orange_voip.env
```

You can also provide environment variables and run `python3 orange-proxy/proxy.py` without a file. Environment variables override matching keys in the file. The file format is literal `KEY=value`, as written by the extractor: no shell expansion or quote processing. Do not add shell quotes around values.

## Configuration

The extractor supplies these settings:

| Variable | Meaning | Default |
| --- | --- | --- |
| `ORANGE_SIP_USERNAME` | SIP authentication identity | Required |
| `ORANGE_SIP_PASSWORD` | SIP authentication password | Required |
| `ORANGE_PHONE_NUMBER` | Telephone number used for the line identity | Required |
| `ORANGE_SIP_DOMAIN` | Domain used in Orange SIP requests | `sip.orange.es` |
| `ORANGE_SIP_PROXY_HOST` | Orange signaling peer | `proxy2.sip.orange.es` |
| `ORANGE_SIP_PROXY_PORT` | Orange signaling port | `5060` |
| `ORANGE_SIP_REGISTER_EXPIRES` | Requested registration lifetime, seconds | `3600` |

Add these settings to the file or environment when needed:

| Variable | Meaning | Default |
| --- | --- | --- |
| `ORANGE_PROXY_BIND_HOST` | Bind address for both SIP sockets | `0.0.0.0` |
| `ORANGE_PROXY_BIND_PORT` | Listener for calls from your SIP server | `5064` |
| `ORANGE_PROXY_DOWNSTREAM_PORT` | Local socket used for Orange registration and calls | `5070` |
| `ORANGE_REGISTER_CONTACT_PORT` | Port advertised in the registration Contact | Downstream port |
| `ORANGE_PROXY_UPSTREAM_HOST` | SIP server receiving incoming calls | `127.0.0.1` |
| `ORANGE_PROXY_UPSTREAM_PORT` | SIP server port | `5060` |
| `ORANGE_PROXY_PUBLIC_HOST` | Address advertised in SIP headers | Local address of the route to Orange |
| `ORANGE_REGISTER_MARGIN` | How early to refresh registration, seconds | `120` |
| `ORANGE_PROXY_INVITE_TIMEOUT` | Setup timeout after a provisional response, seconds | `60` |
| `ORANGE_PROXY_MAX_CALLS` | Combined limit for incoming and outgoing calls, including setup; `0` disables the software limit | `0` |
| `ORANGE_PROXY_USER_AGENT` | SIP User-Agent value | `OrangeBridge/0.1` |
| `ORANGE_PROXY_LOG_LEVEL` | Logging level | `INFO` |
| `ORANGE_PROXY_TRACE_SIP` | Log full SIP messages | `false` |

Existing deployments can keep using these aliases. The canonical name takes precedence when both are provided; empty numeric settings fall back to the alias or default:

| Canonical name | Existing alias |
| --- | --- |
| `ORANGE_SIP_USERNAME` | `ORANGE_AUTH_USERNAME` |
| `ORANGE_SIP_PASSWORD` | `ORANGE_PASSWORD` |
| `ORANGE_PHONE_NUMBER` | `ORANGE_FROM_NUMBER` |
| `ORANGE_SIP_DOMAIN` | `ORANGE_DOMAIN` |
| `ORANGE_SIP_PROXY_HOST` | `ORANGE_PROXY_HOST` |
| `ORANGE_SIP_PROXY_PORT` | `ORANGE_PROXY_PORT` |
| `ORANGE_SIP_REGISTER_EXPIRES` | `ORANGE_REGISTER_EXPIRES` |

The extractor also exports SIP URI, registrar, and outbound-proxy metadata for inspection and the diagnostic client. The bridge connects to `ORANGE_SIP_PROXY_HOST:ORANGE_SIP_PROXY_PORT` and uses the `Service-Route` learned during registration. It does not independently select endpoints from the exported outbound-proxy list.

## Routing and Limitations

```text
Outgoing: SIP server -> bridge UDP 5064 -> Orange
Incoming: Orange -> registered bridge UDP 5070 -> SIP server UDP 5060
Audio:    handled by the SIP server and the remote media endpoint
```

- **Concurrent calls on one registered line.** Each call has independent SIP state. The number of simultaneous conversations also depends on the Orange line and the attached SIP server; the bridge cannot increase the operator's channel capacity.
- **UDP and IPv4 signaling.** It does not implement TCP/TLS SIP transport.
- **No RTP relay or transcoding.** SDP is forwarded; the SIP server must provide reachable media addresses and ports. The bridge does not perform NAT traversal for audio.
- **No authentication on the SIP-server-facing listener.** Restrict UDP `5064` to your trusted SIP server with the host firewall. It must not be exposed as a public dialing endpoint. `ORANGE_PROXY_BIND_HOST` applies to both sockets.
- The automatic advertised address is a local routing address, not public-IP discovery. Configure `ORANGE_PROXY_PUBLIC_HOST` and the network mapping if the peer needs a different reachable address.
- Full SIP tracing redacts Authorization headers but includes telephone numbers, IP addresses, and SDP. Normal logs also contain call identifiers and numbers; redact them before sharing.
- Registration from another endpoint can replace the active Orange contact. Avoid running the bridge and the separate registration test client against the same line at the same time.

The bridge was tested with Orange Spain and LiveKit SIP, including real incoming and outgoing calls. Other SIP servers have not been verified. The extractor's confirmed router is a Livebox 6 Sagemcom F@st 5670 with firmware 01.08.13; this is not a compatibility claim for every Orange service or router.

## Call Capacity and Logs

Set `ORANGE_PROXY_MAX_CALLS=2` to admit up to two incoming/outgoing calls combined. A call occupies a slot from initial admission until local cancellation, failure, or hangup. Excess initial INVITEs receive `486 Busy Here`; retransmissions receive the cached response. In-dialog requests, registration, and transaction retries do not consume new slots. There is no waiting queue.

One event loop reads the two SIP sockets. Requests within a dialog are matched by socket, Call-ID, and both dialog tags, following [RFC 3261 section 12.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.2). CANCEL is matched to its initial transaction. Ending a call removes its active session; transaction state survives independently to handle retransmissions and late answers.

Normal INFO logs contain `call state=...` lines for admitted calls and capacity rejections:

| Field | Meaning |
| --- | --- |
| `state` | `received`, `answered`, `completed`, `cancelled`, `rejected`, `timeout`, or `failed` |
| `direction` | `inbound` from Orange or `outbound` from the attached SIP server |
| `upstream_call_id` | Call-ID on the attached SIP server leg |
| `downstream_call_id` | Call-ID on the Orange leg |
| `active_calls` | Calls currently admitted, after this state change |
| `max_calls` | Configured software limit; `0` means no software limit |
| `reason` | `capacity_limit`, `orange_cancel`, `application_cancel`, `orange_bye`, `application_bye`, `invite_timeout`, `ack_timeout`, `invalid_auth_challenge`, `peer_response`, or `-` |
| `sip_status` | Related SIP status when available; `0` when not applicable |

The log timestamp marks when the bridge observed the transition. `received` means admitted for forwarding; `answered` means the far end returned 200 and the bridge forwarded the answer. Capacity rejections have a terminal line without admission. Both leg IDs are allocated before the capacity check, so a generated ID in a rejection log does not mean an INVITE was sent on that leg. Cancellation and terminal transitions are logged once per session; SIP retries have separate transaction logs.

`orange_cancel` means Orange sent CANCEL. It does not establish whether a person hung up or the operator cancelled setup. `invite_timeout` can result from a peer's 408 or the bridge's transaction timer. A `completed` event marks local hangup handling; ACK/BYE retries may still be pending. These are diagnostic logs, with no HTTP delivery, persistence, or replay guarantee. Integration with an application's call history is separate.

## Optional Docker Usage

On a Linux host, from the repository root:

```bash
docker build -t orange-sip-bridge ./orange-proxy
docker run -d --name orange-sip-bridge \
  --network host \
  --restart unless-stopped \
  --env-file .orange_voip.env \
  orange-sip-bridge
```

The same network and listener restrictions apply. Docker and Compose are not dependencies of the script. This repository does not start a SIP server or change your firewall.

## Use a Specific Version in Another Project

Keep development in this repository and pin the deployed version to a reviewed commit. In a clone, use `git checkout <full-commit-sha>` before running or building the bridge.

Docker can also build directly from that commit without copying the source into another project:

```bash
docker build -t orange-sip-bridge \
  'https://github.com/inlanger/orange-livebox6-voip-tools.git#<full-commit-sha>:orange-proxy'
```

Replace `<full-commit-sha>` with the full 40-character commit hash. The same Git URL can be used as a Compose `build` context in the consuming project. See Docker's [Git build contexts](https://docs.docker.com/build/concepts/context/#git-repositories).

Pushing changes here does not update a running deployment. To deploy a change, update the pinned commit, rebuild, and restart the bridge when no call is active.

## Tests

From the repository root:

```bash
python3 -m unittest discover -s orange-proxy/tests -v
python3 -m unittest discover -s tests -v
```

Tests cover concurrent incoming/outgoing calls, distinct SDP forwarding, shared capacity, independent cancellation/hangup/timeouts, registration refresh during calls, retransmitted and failed INVITEs, ACK matching by dialog tags, cancellation racing with an answer, missing ACKs, and retried BYEs. They use synthetic credentials and local UDP peers, with no operator connection or telephone calls. Concurrent SIP signaling in these tests does not verify simultaneous audio conversations on a particular Orange account.
