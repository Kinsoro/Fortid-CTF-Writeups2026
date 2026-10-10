# Baby Web — Client-Side Obfuscation and Event Handler Bypass | Local CTF

**Category:** Web  
**Difficulty:** Easy  
**Flag Format:** `FortID{...}`  
**Author:** isit  
**Date:** 2026-10-09  


## Executive Summary

The challenge presents a single-page web application with a button that evades clicks by repositioning itself on `mouseenter`. The flag is not fetched from a server—it is embedded in the client-side JavaScript as a reversed, Base64-encoded string. By reading the source directly, the flag is recovered without interacting with the evasion logic: `FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}`. The core weakness is relying on client-side obfuscation and DOM event handlers to protect a secret that the browser must already possess to display.


# Baby Web — Client-Side Obfuscation and Event Handler Bypass | Local CTF

**Category:** Web  
**Difficulty:** Easy  
**Flag Format:** `FortID{...}`  
**Author:** isit  
**Date:** 2026-10-09  

---

## Executive Summary

The challenge presents a single-page web application with a button that evades clicks by repositioning itself on `mouseenter`. The flag is not fetched from a server—it is embedded in the client-side JavaScript as a reversed, Base64-encoded string. By reading the source directly, the flag is recovered without interacting with the evasion logic: `FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}`. The core weakness is relying on client-side obfuscation and DOM event handlers to protect a secret that the browser must already possess to display.

---

## Challenge Overview

> **Baby Web** — The flag is only one click away... if you can catch it! 🏃  
> Use the `index.html` file. Flags use the format `FortID{...}`.

The challenge provides a standalone `index.html` file. No backend, no network services, no authentication. The objective is to obtain the flag displayed after clicking the "Show me the flag" button—which actively flees the cursor.


<img width="1107" height="381" alt="image" src="https://github.com/user-attachments/assets/55aa124a-e2f5-4f8f-9d94-3280e7032756" />


## Environment and Tools

| Tool | Version | Purpose |
|------|---------|---------|
| `cat` / `less` | — | Read the HTML source |
| Python 3 | 3.11+ | Base64 decode and string reversal |
| Web browser (optional) | — | Verify button behavior |

No scanners, proxies, or exploitation frameworks were required.

---

## Methodology and Reconnaissance

### Objective
Understand how the flag is generated and whether the button's evasion logic is a genuine barrier or theater.

### Action
Read the provided `index.html` in full.

```bash
cat /home/isit/CTF/files/index.html
```

### Evidence
The file is a self-contained HTML document (~128 lines). The relevant JavaScript (lines 97–125):

```javascript
const button = document.querySelector("#runaway");
const output = document.querySelector("#flag");

function runAway() {
  const padding = 16;
  const maxX = Math.max(padding, window.innerWidth - button.offsetWidth - padding);
  const maxY = Math.max(padding, window.innerHeight - button.offsetHeight - padding);

  button.style.transform = "none";
  button.style.left = `${padding + Math.random() * (maxX - padding)}px`;
  button.style.top = `${padding + Math.random() * (maxY - padding)}px`;
}

button.addEventListener("mouseenter", runAway);

button.addEventListener("click", () => {
  const scrambled = [
    "=0XNx81Nx81auFDa38Vdwk3",
    "X1QzXkJHNo91N0g2NfdDMu9V",
    "Nx8lYzc3eElEdy9mR"
  ].join("");

  output.textContent = atob([...scrambled].reverse().join(""));
  output.classList.add("success");
  button.textContent = "You caught me!";
  button.removeEventListener("mouseenter", runAway);
  button.disabled = true;
});
```

### Interpretation
- The `runAway()` function repositions the button on `mouseenter`, making it difficult to click.
- The `click` handler constructs `scrambled` by concatenating three string literals.
- It then reverses the character array (`[...scrambled].reverse().join("")`) and passes the result to `atob()` (Base64 decode).
- The decoded string is written to `#flag`.
- **Critical observation:** The flag material is entirely in the source. The button click is not a gate—it is a presentation step. The browser already holds the secret.

### Next Step
Decode the string statically; no browser interaction required.

---

## Vulnerability Analysis / Key Discovery

**Component:** Client-side JavaScript in `index.html`  
**Weakness:** Secret material embedded in code delivered to the client, protected only by reversible obfuscation (string split + reversal + Base64) and a UI evasion trick.

**Root Cause:** The flag is not derived from server state, user input, or a cryptographic challenge. It is a static constant disguised by trivial encoding. Any observer with the HTML source can recover it.

**Trust Boundary Violation:** The challenge assumes the user must "catch" the button. In reality, the trust boundary is the client's renderer—which the user fully controls. The evasion is a UI/UX puzzle, not a security control.

**Prerequisites & Limitations:**
- Access to the HTML file (provided by the challenge).
- No network access, no authentication, no special privileges needed.

**Impact:** Full flag disclosure without triggering the intended interaction.

---

## Exploitation / Solution Walkthrough

### Step 1: Extract the Scrambled String

The three fragments are concatenated in source order:

```text
"=0XNx81Nx81auFDa38Vdwk3" +
"X1QzXkJHNo91N0g2NfdDMu9V" +
"Nx8lYzc3eElEdy9mR"
```

Result:

```
=0XNx81Nx81auFDa38Vdwk3X1QzXkJHNo91N0g2NfdDMu9VNx8lYzc3eElEdy9mR
```

### Step 2: Reverse the Character Sequence

```python
scrambled = "=0XNx81Nx81auFDa38Vdwk3X1QzXkJHNo91N0g2NfdDMu9VNx8lYzc3eElEdy9mR"
reversed_str = scrambled[::-1]
```

Reversed:

```
Rm9ydElEe3czYl8xNV9uMDdfN2g0N19oNHJkXzQ1X3kwdV83aDFua18xN18xNX0=
```

### Step 3: Base64 Decode

```python
import base64
flag = base64.b64decode(reversed_str).decode()
print(flag)
```

Output:

```
FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}
```

### Verification

The decoded string matches the expected `FortID{...}` format and is a coherent leetspeak sentence:  
"web is not that hard as you think it is".

---

## Flag Retrieval and Verification

```
FortID{w3b_15_n07_7h47_h4rd_45_y0u_7h1nk_17_15}
```

Verified by:
1. Static decode of the embedded constant.
2. Loading `index.html` in a browser, clicking the button (after disabling the `mouseenter` listener in DevTools), and observing the same output in `#flag`.

---

## Root Cause and Remediation

### Root Cause
The flag was stored in the client bundle as a statically encoded string. The only "protection" was:
1. Splitting the Base64 payload across three literals.
2. Reversing the character order.
3. A `mouseenter` handler that moves the button.

All three are reversible by anyone with the source.

### Remediation (for Real Applications)
- **Never embed secrets in client-side code.** Flags, API keys, tokens, and sensitive logic belong server-side.
- **If a client-side puzzle is intentional**, accept that the solution is readable in source. Use it as a learning exercise, not a security control.
- **Obfuscation ≠ security.** Reversal, Base64, XOR, or minification only raise the bar for casual viewers; they do not stop a motivated analyst.
- **UI tricks are not access controls.** Disabling buttons, hiding elements, or moving targets can be bypassed via DevTools, `console`, or direct DOM manipulation.

### Challenge-Specific Note
This is an intentionally vulnerable CTF artifact designed to teach source inspection and decoding basics. The "vulnerability" is the intended solving path. In production, the same pattern—shipping a secret to the client and hiding it behind UI logic—is a critical design flaw.

---

## Lessons Learned

- **Read the source first.** The fastest path to the flag was `cat index.html`, not chasing a button.
- **Client-side secrets are not secret.** Anything delivered to the browser—JavaScript, WASM, HTML, CSS—can be inspected, decoded, and replayed.
- **Obfuscation layers are trivial to peel.** String concatenation, reversal, and Base64 add zero cryptographic strength.
- **Event handlers are suggestions.** `mouseenter`, `click`, `keydown`—all can be removed, triggered programmatically, or bypassed via the console.

---

## References

- [MDN: `atob()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/atob) — Base64 decoding in browsers.
- [MDN: `EventTarget.addEventListener()`](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener) — Event handler registration and removal.
- [OWASP: Client-Side Security](https://owasp.org/www-project-top-ten/) — Risks of trusting the client.





