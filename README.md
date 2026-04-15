# Orange Livebox 6 VoIP Tools

Small, dependency-free tools for Orange Spain `Livebox 6` SIP extraction and signaling tests.

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
  Example environment file consumed by the test script.

## Prerequisites

- Python 3.10+
- Local access to the Livebox LAN
- The `Wi-Fi key` printed on the router sticker
- A network path to Orange SIP servers for signaling tests

## Browser / Network Notes

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
curl -k -u "$AUTH" "$BASE/VoIP/SIP/Lines/%2B34960712434"
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

### Print extracted values and dotenv lines

```bash
python3 scripts/extract_livebox_sip.py \
  --host 192.168.1.1 \
  --password '<WIFI_KEY_FROM_STICKER>'
```

### Write a dotenv file

```bash
python3 scripts/extract_livebox_sip.py \
  --host 192.168.1.1 \
  --password '<WIFI_KEY_FROM_STICKER>' \
  --env-file .orange_voip.env
```

### Dump raw JSON payloads for inspection

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
