![Orange VoIP bridge connecting two simultaneous phone calls](assets/readme-banner.png)

# Orange Livebox 6 VoIP Tools

Dependency-free Python tools for Orange Spain: extract `Livebox 6` SIP credentials, check registration, and bridge incoming and outgoing calls to a SIP server.

The extractor and bridge use the same credential file. The bridge runs on its own; Docker is an optional way to run it. No PBX, voice agent, or media server is bundled.

This repository is based on a `Livebox 6 Sagemcom F@st 5670` with firmware `01.08.13`, where the working flow was:

1. Query the local router API over HTTPS with `UsrAdmin + Wi-Fi key`.
2. Read SIP metadata from `/API/1.0/VoIP/SIP`.
3. Read line credentials from `/API/1.0/VoIP/SIP/Lines/%2B<phone-number>`.
4. Register to Orange with `Expires: 3600`.
5. Reuse the returned `Service-Route` for outbound INVITE tests.

The scripts here do not depend on `LiveboxFibraExtractor`.

## Repository Layout

- `scripts/extract_livebox_sip.py`
  Read-only extractor for Livebox API data and dotenv output.
- `scripts/test_orange_sip.py`
  Raw SIP test client for `REGISTER` and short `ring-once` call tests.
- `examples/orange_voip.env.example`
  Example environment file for the SIP test client and bridge.
- `orange-proxy/proxy.py`
  Persistent SIP registration and call bridge. See the [bridge instructions](orange-proxy/README.md) for routing, configuration, and Docker usage.
- `orange-proxy/tests/`
  Registration, call lifecycle, and local UDP regression tests.
- `tests/`
  Shared configuration and credential-handling tests.

## Extract and Run

```bash
python3 scripts/extract_livebox_sip.py \
  --host 192.168.1.1 \
  --password '<WIFI_KEY_FROM_STICKER>' \
  --env-file .orange_voip.env

python3 orange-proxy/proxy.py --env-file .orange_voip.env
```

The bridge listens for calls from your SIP server on UDP port `5064`, registers with Orange from UDP port `5070`, and forwards incoming calls to `127.0.0.1:5060`. Configure your SIP server and restrict access to the bridge's unauthenticated local listener before running it. See [routing and limitations](orange-proxy/README.md#routing-and-limitations).

The SIP password is hidden in terminal output by default. The generated file contains the actual password and is saved with mode `600` on POSIX systems. Use `--show-secrets` only when you want to print the password.

## Prerequisites

- Python 3.10+
- Local access to the Livebox LAN
- The `Wi-Fi key` printed on the router sticker
- A network path to Orange SIP servers for signaling tests

## Browser / Network Notes

- Run the bridge through your Orange home connection first. In our test, the same bridge image and credentials registered successfully from home but received no SIP responses from either Orange proxy address on an OVH VPS. Both proxies also accepted TCP connections from home but timed out from the VPS; another SIP service was reachable from the VPS.
- This suggests a source-network restriction. It does not establish whether Orange requires the original subscriber line, allows other Orange connections, or whether the failure is specific to the OVH route. Extracted credentials alone do not guarantee registration from a remote server.
- The Livebox certificate is self-signed. Browsers often show `ERR_CERT_INVALID`.
- The scripts use HTTPS with certificate verification disabled on purpose for local extraction.
- If your main router and Livebox both use `192.168.1.1`, isolate the Livebox or make sure your Ethernet interface is routed directly to it.

## Direct API Calls

The working API user on this model was `UsrAdmin`, and the password was the Wi-Fi key from the sticker.

```bash
AUTH='UsrAdmin:<WIFI_KEY_FROM_STICKER>'
BASE='https://192.168.1.1/API/1.0'

curl -k -u "$AUTH" "$BASE/VoIP"
curl -k -u "$AUTH" "$BASE/VoIP/SIP"
curl -k -u "$AUTH" "$BASE/VoIP/SIP/Lines"
curl -k -u "$AUTH" "$BASE/VoIP/SIP/Lines/%2B34960000000"
curl -k -u "$AUTH" "https://192.168.1.1/API/WAN"
```

## Which Data We Took, And From Where

### From `/API/1.0/VoIP/SIP`

These fields were used to build SIP routing settings:

- `userAgentDomain`
- `proxyServer`
- `proxyServerPort`
- `outboundProxyServer`
- `outboundProxyServerPort`
- `registrarServer`
- `registrarServerPort`

### From `/API/1.0/VoIP/SIP/Lines/%2B<phone-number>`

These fields were used as the actual line credentials:

- `directoryNumber` / `name`
- `uri`
- `authUserName`
- `authPassword`

### From `/API/WAN`

This is optional, but useful as a sanity check:

- `MACAddress`
- `LinkState`
- `ConnectionState`

## Extractor Usage

### Print extracted values with the password hidden

```bash
python3 scripts/extract_livebox_sip.py \
  --host 192.168.1.1 \
  --password '<WIFI_KEY_FROM_STICKER>'
```

Add `--show-secrets` to include the SIP password in the terminal output. Use `--env-file` to create a usable credential file without printing its password.

### Write a dotenv file

```bash
python3 scripts/extract_livebox_sip.py \
  --host 192.168.1.1 \
  --password '<WIFI_KEY_FROM_STICKER>' \
  --env-file .orange_voip.env
```

### Dump raw JSON payloads for inspection

Raw dumps include credentials. Each JSON file is saved with mode `600` on POSIX systems.

```bash
python3 scripts/extract_livebox_sip.py \
  --host 192.168.1.1 \
  --password '<WIFI_KEY_FROM_STICKER>' \
  --dump-dir dumps
```

## Test Script Usage

The SIP test script reads its values from environment variables or a dotenv file.

### Register only

```bash
python3 scripts/test_orange_sip.py \
  --env-file .orange_voip.env \
  --mode register
```

### Ring a destination and cancel after the first `180 Ringing`

```bash
python3 scripts/test_orange_sip.py \
  --env-file .orange_voip.env \
  --mode ring-once \
  --destination +34600000000
```

## The Working Signaling Pattern

The working pattern for Orange Spain was:

1. `REGISTER sip:sip.orange.es SIP/2.0`
2. Expect `401 Unauthorized`
3. Re-send `REGISTER` with Digest auth and `Expires: 3600`
4. Expect `200 OK`
5. Read `Service-Route` from the registration response
6. Send `INVITE sip:+34...@sip.orange.es` using that route

Without the prior `REGISTER`, outbound INVITE tests can fail with `403 Forbidden`.

## What Can Go Wrong

- `401` from the Livebox API:
  You used `admin` instead of `UsrAdmin`, or the Wi-Fi key is wrong.
- `423 Interval Too Brief` on SIP REGISTER:
  Orange wants `Expires: 3600`.
- `403 Forbidden` on INVITE:
  Usually means you skipped `REGISTER`, used the wrong Request-URI, or did not reuse the route learned during registration.
- `180 Ringing` followed by the phone continuing to ring for a couple of seconds:
  This can still happen after `CANCEL`; the mobile/PSTN side may already be alerting.
- No audio:
  The test script is signaling-first. It sends SDP, but it is not a real media endpoint or PBX.
- Multiple SIP endpoints:
  Registering a new contact can expire the previous one. Orange may keep only one active contact.

## Security

- Treat `authUserName` and `authPassword` as secrets.
- Do not commit real credentials into the repository.
- Rotate or recover the line through Orange/Livebox if you leak them.

## Tests

```bash
python3 -m unittest discover -s orange-proxy/tests -v
python3 -m unittest discover -s tests -v
```

These tests use synthetic credentials, mocks, and UDP peers on localhost. They do not contact Orange or place telephone calls. One regression test waits longer than the 32-second SIP ACK deadline, so the bridge suite takes roughly 35 seconds.

GitHub Actions runs both suites on pushes and pull requests with Python 3.10 and 3.12.
