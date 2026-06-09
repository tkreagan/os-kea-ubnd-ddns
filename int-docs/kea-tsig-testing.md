# Kea TSIG — Implementation Notes & Testing Plan

> Notes for the TSIG end-to-end validation round. The implementation is present in
> the plugin and the OPNsense model; the end-to-end path has never been exercised.
> These notes consolidate what is known before testing begins.

## What is already implemented

**Listener (`kea-unbound-ddns.py`):**
- `--tsig-key NAME:SECRET` argument (base64 secret)
- `--tsig-algorithm ALGO` (default `HMAC-SHA256`)
- Enforced as all-or-nothing: if `--tsig-key` is passed, unsigned packets are
  **REFUSED** (`dns.rcode.REFUSED`). Signed packets with wrong key raise
  `dns.exception.DNSException` during parse — caught, logged, packet dropped.
- Supported algorithms: HMAC-MD5, HMAC-SHA1, HMAC-SHA224, HMAC-SHA256, HMAC-SHA384,
  HMAC-SHA512
- Key parsing: `parse_tsig_key()` → `dns.tsigkeyring.from_text({name: (algo, secret)})`

**OPNsense model (per-subnet, both v4 and v6):**
- `ddns_domain_key_name` — TSIG key name (TextField)
- `ddns_domain_key_secret` — TSIG secret (Base64Field)
- `ddns_domain_key_algorithm` — algorithm (OptionField)

**D2 side (`kea-dhcp-ddns.conf`):**
- `tsig-keys[]` — global key definitions: `name`, `algorithm`, `secret` (or `secret-file`)
- Per forward/reverse domain: `key-name` references a key from `tsig-keys[]`
- D2 signs NCR→UPDATE packets with that key before sending to the DNS server

**Plugin settings (`GeneralController.php` / `General.xml`):**
- TSIG key name + secret + algorithm at the plugin level (for the listener)
- These are passed to `kea-unbound-ddns.py` via `start.py` as `--tsig-key`/`--tsig-algorithm`

## The all-or-nothing enforcement

The listener enforces TSIG symmetrically:

```
Listener started WITH --tsig-key:
  - Signed packet, key matches    → authenticate, process
  - Signed packet, key wrong      → DNSException at parse → drop (log warning)
  - Unsigned packet               → REFUSED response

Listener started WITHOUT --tsig-key:
  - Unsigned packet               → process normally
  - Signed packet                 → dnspython verifies against keyring=None
    → behavior depends on dnspython version — may accept or raise
    → should be tested; expected: accepted (no keyring = no enforcement)
```

## Failure modes to test

| Scenario | D2 config | Listener config | Expected outcome |
|----------|-----------|-----------------|-----------------|
| **Happy path — TSIG on both** | key `mykey` SHA256, domain uses it | `--tsig-key mykey:SECRET` | Update signed, authenticated, registered ✅ |
| **D2 key, listener no key** | key configured, domain uses it | no `--tsig-key` | Signed packets arrive; listener behavior unknown (test) |
| **Listener key, D2 no key** | no key | `--tsig-key mykey:SECRET` | Unsigned packets → REFUSED; no records registered |
| **Algorithm mismatch** | domain uses HMAC-MD5 | listener `--tsig-algorithm HMAC-SHA256` | dnspython auth fails at parse → packet dropped |
| **Secret mismatch** | correct name, wrong secret | correct name, different secret | dnspython auth fails at parse → packet dropped |
| **Key name mismatch** | key `rightname` | listener has `wrongname` | dnspython: keyring lookup fails → drop |

## Key generation for testing

```bash
# Generate a random HMAC-SHA256 key secret (32 bytes → 44 char base64)
openssl rand -base64 32

# Format for D2 tsig-keys[]:
# { "name": "testkey", "algorithm": "HMAC-SHA256", "secret": "<base64>" }

# Format for listener --tsig-key:
# testkey:<base64>
```

## Where to configure in OPNsense

**Plugin-side key (listener):**
Services → Kea Unbound → Settings → Enable TSIG authentication (key name + secret + algorithm)

**D2-side key (per subnet):**
Services → Kea DHCP → Kea DHCPv4 → Subnets → Edit → Dynamic DNS → Advanced →
TSIG key name + TSIG secret + TSIG algorithm

Both sides must match: same name, same secret (base64), same algorithm.

## Config Check tab behavior with TSIG

The `KcaconfigController.php` already detects TSIG mismatch (`tsig_mismatch` status):
it reads the per-domain key from D2's conf and compares it with the plugin's configured
key. The fix guide in `kcaconfig.volt` explains how to align both sides.

The `tsig_mismatch` bucket captures: one side has a key, the other does not; or both
have keys but they don't match.

## Protocol-level detail

D2 signs the DNS UPDATE packet using the TSIG algorithm before sending via UDP to
`127.0.0.1:53535`. The TSIG record is appended as an additional record in the packet.
dnspython's `dns.message.from_wire(data, keyring=keyring)` verifies the TSIG MAC
before returning the parsed message. On failure it raises `dns.exception.DNSException`.

TSIG does not encrypt the packet — it provides authentication only (the DNS UPDATE
contents are plaintext). On a loopback interface this is low-risk; the value of TSIG
here is preventing rogue local processes from injecting DNS updates.

## OPNsense config.xml location

```xml
<!-- Plugin-level TSIG (listener) -->
<KeaUnbound>
  <general>
    <tsig_enabled>1</tsig_enabled>
    <tsig_key_name>testkey</tsig_key_name>
    <tsig_key_secret>base64secrethere=</tsig_key_secret>
    <tsig_algorithm>HMAC-SHA256</tsig_algorithm>
  </general>
</KeaUnbound>

<!-- Per-subnet TSIG (D2 domain) — in KeaDhcpv4 subnet node -->
<ddns_domain_key_name>testkey</ddns_domain_key_name>
<ddns_domain_key_secret>base64secrethere=</ddns_domain_key_secret>
<ddns_domain_key_algorithm>HMAC-SHA256</ddns_domain_key_algorithm>
```

## ncr-protocol reminder

D2 uses `ncr-protocol: UDP` (only supported value as of Kea 3.0). The listener is
`SOCK_DGRAM` only. A manual config setting `ncr-protocol: TCP` would cause silent
update loss. The Config Check tab should warn on `ncr-protocol != "UDP"` when reading
the D2 config — this is a TODO in `KcaconfigController.php`.

## Test sequence (listener round)

1. Generate key. Set `ddns_domain_key_*` on the test subnet. Verify D2 conf has it.
2. Set plugin TSIG key in Settings. Restart plugin (daemon picks up new args).
3. **Happy path:** DORA from dev-dhcpclient → confirm A+PTR registered.
4. **Secret mismatch:** change listener secret → confirm packets dropped (listener log
   shows parse exception), no records registered.
5. **D2 key, listener no key:** disable plugin TSIG → confirm REFUSED in listener log,
   no records.
6. **Listener key, D2 no key:** disable D2 TSIG → unsigned packets arrive → test whether
   listener rejects or processes them.
7. **Algorithm mismatch:** set D2 to HMAC-MD5, listener HMAC-SHA256 → confirm drop.

## Known gaps / deferred

- `secret-file` (D2 reads key from a file) — not tested; plugin doesn't support file-based
  key on the listener side either.
- Key rotation (change secret while daemon running) — daemon must restart to pick up new
  `--tsig-key`. Document this in the settings UI.
- Multiple keys / per-domain key selection — D2 supports different keys per domain;
  plugin has one global key. If forward and reverse domains used different keys, only one
  would work. Not a real-world issue (same listener port, one key suffices).
